//! Linux whole-device TUN adapter for the signed device-routing client.
//!
//! The userspace TCP/UDP stack is provided by the audited `tun2proxy` crate,
//! while RandallFlare deliberately owns policy routing.  Keeping the route
//! lifecycle here lets us install the catch-all last, remove it first, bypass
//! management traffic, and leave the host's main routing table untouched.

#[cfg(target_os = "linux")]
mod linux {
    use crate::exitproxy::DeviceConfig;
    use anyhow::{bail, Context, Result};
    use std::collections::BTreeSet;
    use std::fs;
    use std::future::Future;
    use std::io::{BufRead, BufReader};
    use std::net::{IpAddr, SocketAddr};
    use std::os::fd::AsRawFd;
    use std::path::Path;
    use std::pin::Pin;
    use std::process::Command;
    use std::time::Duration;
    use tokio::net::TcpStream;

    const PREF_SSH: u32 = 27_359;
    const PREF_VPN: u32 = 27_365;
    const PREF_MARK: u32 = 27_370;
    const PREF_DNS: u32 = 27_375;
    const PREF_BYPASS: u32 = 27_380;
    const PREF_TUN: u32 = 27_400;
    const TAILSCALE_MARK: &str = "0x80000/0xff0000";
    const SSH_PORTS: &[u16] = &[22, 2222];

    const DEFAULT_BYPASS_V4: &[&str] = &[
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
    ];
    const DEFAULT_BYPASS_V6: &[&str] = &["::1/128", "fc00::/7", "fe80::/10", "ff00::/8"];

    #[derive(Debug, Clone)]
    pub struct Options {
        pub name: String,
        pub mtu: u16,
        pub mark: u32,
        pub table: u32,
        pub ipv6: bool,
        pub bypass: Vec<String>,
        pub dns_servers: Vec<IpAddr>,
        pub max_sessions: usize,
        pub deadman_seconds: u64,
    }

    impl Default for Options {
        fn default() -> Self {
            Self {
                name: "rf-tun0".into(),
                mtu: 1400,
                mark: 0x52f1,
                table: 7388,
                ipv6: true,
                bypass: Vec::new(),
                dns_servers: Vec::new(),
                max_sessions: 512,
                deadman_seconds: 300,
            }
        }
    }

    impl Options {
        pub fn validate(&self) -> Result<()> {
            if self.name.is_empty()
                || self.name.len() > 15
                || !self
                    .name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
            {
                bail!("TUN 接口名必须是 1–15 位 ASCII 字母、数字、点、下划线或连字符");
            }
            if !(576..=9000).contains(&self.mtu) {
                bail!("TUN MTU 必须在 576–9000 之间");
            }
            if self.mark == 0 {
                bail!("TUN socket mark 不得为 0");
            }
            if self.table == 0 || matches!(self.table, 253..=255) {
                bail!("TUN 路由表不得使用 0、default、main 或 local 表");
            }
            if self.max_sessions == 0 || self.max_sessions > 65_536 {
                bail!("TUN 最大会话数必须在 1–65536 之间");
            }
            if self.deadman_seconds < 60 {
                bail!("TUN 失联自救时间不得短于 60 秒");
            }
            for value in &self.bypass {
                normalize_cidr(value)?;
            }
            if self
                .dns_servers
                .iter()
                .any(|address| address.is_loopback() || address.is_unspecified())
            {
                bail!("TUN 旁路 DNS 上游不得是回环或未指定地址");
            }
            Ok(())
        }
    }

    pub fn open_device(options: &Options) -> Result<tun::AsyncDevice> {
        options.validate()?;
        let mut config = tun::Configuration::default();
        config
            .address((10, 120, 0, 2))
            .destination((10, 120, 0, 1))
            .netmask((255, 255, 255, 0))
            .mtu(options.mtu)
            .tun_name(&options.name)
            .up();
        config.platform_config(|platform| {
            #[allow(deprecated)]
            platform.packet_information(true);
            platform.ensure_root_privileges(true);
        });
        tun::create_as_async(&config).context(
            "创建 Linux TUN 失败；请确认 /dev/net/tun 可用且进程拥有 root 或 CAP_NET_ADMIN",
        )
    }

    pub fn tun_name(device: &tun::AsyncDevice) -> Result<String> {
        tun::AbstractDevice::tun_name(&**device).context("读取 TUN 接口名")
    }

    pub fn stack_args(proxy: SocketAddr, options: &Options) -> Result<tun2proxy::Args> {
        let mut args = tun2proxy::Args::default();
        args.proxy = tun2proxy::ArgProxy::try_from(format!("socks5://{proxy}").as_str())
            .map_err(|error| anyhow::anyhow!("构造内置 SOCKS 地址失败：{error}"))?;
        args.dns = tun2proxy::ArgDns::Virtual;
        args.ipv6_enabled = options.ipv6;
        args.mtu = options.mtu;
        args.tcp_mss = Some(options.mtu.saturating_sub(40));
        args.tcp_timeout = 600;
        args.udp_timeout = 60;
        args.max_sessions = options.max_sessions;
        args.exit_on_fatal_error = true;
        Ok(args)
    }

    pub async fn automatic_bypass(
        control: &str,
        config: &DeviceConfig,
        requested: &[String],
    ) -> Result<Vec<String>> {
        let mut result = BTreeSet::new();
        result.extend(DEFAULT_BYPASS_V4.iter().map(|value| (*value).to_string()));
        result.extend(DEFAULT_BYPASS_V6.iter().map(|value| (*value).to_string()));
        for value in requested {
            result.insert(normalize_cidr(value)?);
        }
        for address in ssh_peers()? {
            result.insert(host_cidr(address));
        }
        if let Ok(url) = reqwest::Url::parse(control) {
            if let Some(host) = url.host_str() {
                let port = url.port_or_known_default().unwrap_or(443);
                for address in resolve_host(host, port).await {
                    result.insert(host_cidr(address.ip()));
                }
            }
        }
        for exit in &config.exits {
            if let Some((host, port)) = split_endpoint(&exit.endpoint) {
                for address in resolve_host(&host, port).await {
                    result.insert(host_cidr(address.ip()));
                }
            }
        }
        Ok(result.into_iter().collect())
    }

    async fn resolve_host(host: &str, port: u16) -> Vec<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return vec![SocketAddr::new(ip, port)];
        }
        tokio::net::lookup_host((host, port))
            .await
            .map(|addresses| addresses.collect())
            .unwrap_or_default()
    }

    fn split_endpoint(endpoint: &str) -> Option<(String, u16)> {
        if let Ok(address) = endpoint.parse::<SocketAddr>() {
            return Some((address.ip().to_string(), address.port()));
        }
        let (host, port) = endpoint.rsplit_once(':')?;
        Some((
            host.trim_matches(['[', ']']).to_string(),
            port.parse().ok()?,
        ))
    }

    fn normalize_cidr(value: &str) -> Result<String> {
        let value = value.trim();
        if let Some((address, prefix)) = value.split_once('/') {
            let address: IpAddr = address
                .parse()
                .with_context(|| format!("TUN 旁路地址 {value} 无效"))?;
            let prefix: u8 = prefix
                .parse()
                .with_context(|| format!("TUN 旁路前缀 {value} 无效"))?;
            let maximum = if address.is_ipv4() { 32 } else { 128 };
            if prefix > maximum {
                bail!("TUN 旁路前缀 {value} 超出 IPv4/IPv6 范围");
            }
            Ok(format!("{address}/{prefix}"))
        } else {
            let address: IpAddr = value
                .parse()
                .with_context(|| format!("TUN 旁路地址 {value} 无效"))?;
            Ok(host_cidr(address))
        }
    }

    fn host_cidr(address: IpAddr) -> String {
        format!("{address}/{}", if address.is_ipv4() { 32 } else { 128 })
    }

    fn dns_servers() -> Result<Vec<IpAddr>> {
        let mut result = Vec::new();
        for path in [
            Path::new("/etc/resolv.conf"),
            Path::new("/run/systemd/resolve/resolv.conf"),
        ] {
            let Ok(file) = fs::File::open(path) else {
                continue;
            };
            for line in BufReader::new(file).lines() {
                let line = line?;
                let mut fields = line.split_whitespace();
                if fields.next() != Some("nameserver") {
                    continue;
                }
                if let Some(address) = fields.next().and_then(|value| value.parse().ok()) {
                    if !IpAddr::is_loopback(&address) && !IpAddr::is_unspecified(&address) {
                        result.push(address);
                    }
                }
            }
        }
        Ok(result)
    }

    #[derive(Clone)]
    struct MarkedRuntime {
        inner: hickory_resolver::net::runtime::TokioRuntimeProvider,
        mark: u32,
    }

    impl hickory_resolver::net::runtime::RuntimeProvider for MarkedRuntime {
        type Handle = hickory_resolver::net::runtime::TokioHandle;
        type Timer = hickory_resolver::net::runtime::TokioTime;
        type Udp = tokio::net::UdpSocket;
        type Tcp = hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd<TcpStream>;

        fn create_handle(&self) -> Self::Handle {
            self.inner.create_handle()
        }

        fn connect_tcp(
            &self,
            server_addr: SocketAddr,
            bind_addr: Option<SocketAddr>,
            wait_for: Option<Duration>,
        ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Tcp>>>> {
            let mark = self.mark;
            Box::pin(async move {
                let socket = if server_addr.is_ipv4() {
                    tokio::net::TcpSocket::new_v4()
                } else {
                    tokio::net::TcpSocket::new_v6()
                }?;
                set_socket_mark(&socket, mark)?;
                if let Some(bind_addr) = bind_addr {
                    socket.bind(bind_addr)?;
                }
                socket.set_nodelay(true)?;
                let stream = tokio::time::timeout(
                    wait_for.unwrap_or(Duration::from_secs(5)),
                    socket.connect(server_addr),
                )
                .await
                .map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::TimedOut, "DNS TCP 连接超时")
                })??;
                Ok(hickory_resolver::net::runtime::iocompat::AsyncIoTokioAsStd(
                    stream,
                ))
            })
        }

        fn bind_udp(
            &self,
            local_addr: SocketAddr,
            _server_addr: SocketAddr,
        ) -> Pin<Box<dyn Send + Future<Output = std::io::Result<Self::Udp>>>> {
            let mark = self.mark;
            Box::pin(async move {
                let socket = tokio::net::UdpSocket::bind(local_addr).await?;
                set_socket_mark(&socket, mark)?;
                Ok(socket)
            })
        }
    }

    fn set_socket_mark<T: AsRawFd>(socket: &T, mark: u32) -> std::io::Result<()> {
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_MARK,
                (&mark as *const u32).cast(),
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    /// DNS resolver used only by RandallFlare's own routing process. Its UDP
    /// and TCP sockets carry the bypass mark, while application DNS remains
    /// unmarked and is intercepted by the virtual-DNS rule for domain policy.
    pub struct MarkedResolver {
        resolver: hickory_resolver::Resolver<MarkedRuntime>,
    }

    impl MarkedResolver {
        pub fn new(mark: u32, configured: &[IpAddr]) -> Result<Self> {
            let servers = if configured.is_empty() {
                dns_servers()?
            } else {
                configured.to_vec()
            };
            if servers.is_empty() {
                bail!(
                    "未找到非回环 DNS 上游；请检查 /run/systemd/resolve/resolv.conf 或 /etc/resolv.conf"
                );
            }
            let config = hickory_resolver::config::ResolverConfig::from_parts(
                None,
                Vec::new(),
                servers
                    .into_iter()
                    .map(hickory_resolver::config::NameServerConfig::udp_and_tcp)
                    .collect(),
            );
            let mut options = hickory_resolver::config::ResolverOpts::default();
            options.timeout = Duration::from_secs(5);
            options.attempts = 2;
            let resolver = hickory_resolver::Resolver::builder_with_config(
                config,
                MarkedRuntime {
                    inner: hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
                    mark,
                },
            )
            .with_options(options)
            .build()
            .context("创建 TUN 旁路 DNS 解析器")?;
            Ok(Self { resolver })
        }

        pub async fn lookup(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok(vec![SocketAddr::new(ip, port)]);
            }
            let lookup = self
                .resolver
                .lookup_ip(host.trim_end_matches('.'))
                .await
                .with_context(|| format!("通过标记 DNS 解析 {host}"))?;
            let mut addresses = lookup
                .iter()
                .map(|ip| SocketAddr::new(ip, port))
                .collect::<Vec<_>>();
            addresses.sort();
            addresses.dedup();
            if addresses.is_empty() {
                bail!("标记 DNS 没有返回 {host} 的地址");
            }
            Ok(addresses)
        }
    }

    fn ssh_peers() -> Result<Vec<IpAddr>> {
        let mut result = Vec::new();
        for (path, ipv6) in [
            (Path::new("/proc/net/tcp"), false),
            (Path::new("/proc/net/tcp6"), true),
        ] {
            let Ok(file) = fs::File::open(path) else {
                continue;
            };
            for line in BufReader::new(file).lines().skip(1) {
                if let Some(address) = parse_proc_tcp_line(&line?, ipv6) {
                    result.push(address);
                }
            }
        }
        Ok(result)
    }

    fn parse_proc_tcp_line(line: &str, ipv6: bool) -> Option<IpAddr> {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 4 || fields[3] != "01" {
            return None;
        }
        let (_, local_port) = fields[1].rsplit_once(':')?;
        let local_port = u16::from_str_radix(local_port, 16).ok()?;
        if !SSH_PORTS.contains(&local_port) {
            return None;
        }
        let (remote, _) = fields[2].rsplit_once(':')?;
        parse_proc_ip(remote, ipv6)
            .filter(|address| !IpAddr::is_loopback(address) && !IpAddr::is_unspecified(address))
    }

    fn parse_proc_ip(value: &str, ipv6: bool) -> Option<IpAddr> {
        let bytes = hex::decode(value).ok()?;
        if !ipv6 {
            let bytes: [u8; 4] = bytes.try_into().ok()?;
            return Some(IpAddr::V4(std::net::Ipv4Addr::new(
                bytes[3], bytes[2], bytes[1], bytes[0],
            )));
        }
        let bytes: [u8; 16] = bytes.try_into().ok()?;
        let mut address = [0u8; 16];
        for offset in (0..16).step_by(4) {
            address[offset..offset + 4].copy_from_slice(
                &bytes[offset..offset + 4]
                    .iter()
                    .rev()
                    .copied()
                    .collect::<Vec<_>>(),
            );
        }
        Some(IpAddr::V6(std::net::Ipv6Addr::from(address)))
    }

    #[derive(Debug, Clone)]
    struct Rule {
        ipv6: bool,
        args: Vec<String>,
    }

    /// Owns only RandallFlare's additive rules. Drop always removes the
    /// catch-all before the bypass rules and flushes the dedicated table.
    pub struct RouteGuard {
        options: Options,
        rules: Vec<Rule>,
        bypass: Vec<String>,
        rp_filter: Vec<(String, String)>,
        restored: bool,
    }

    impl RouteGuard {
        pub fn install(options: Options, tun_name: &str, bypass: Vec<String>) -> Result<Self> {
            options.validate()?;
            let mut guard = Self {
                options,
                rules: Vec::new(),
                bypass,
                rp_filter: Vec::new(),
                restored: false,
            };
            guard.clear_stale_core(tun_name);
            run_ip(&[
                "route",
                "replace",
                "default",
                "dev",
                tun_name,
                "table",
                &guard.options.table.to_string(),
            ])?;
            if guard.options.ipv6 {
                run_ip(&[
                    "-6",
                    "route",
                    "replace",
                    "default",
                    "dev",
                    tun_name,
                    "table",
                    &guard.options.table.to_string(),
                ])?;
            }

            for cidr in guard.bypass.clone() {
                let args = vec![
                    "pref".into(),
                    PREF_BYPASS.to_string(),
                    "to".into(),
                    cidr.clone(),
                    "lookup".into(),
                    "main".into(),
                ];
                delete_all_rules(cidr.contains(':'), &args);
                guard.add_rule(cidr.contains(':'), args)?;
            }
            for port in SSH_PORTS {
                guard.add_rule(
                    false,
                    vec![
                        "pref".into(),
                        PREF_SSH.to_string(),
                        "sport".into(),
                        port.to_string(),
                        "lookup".into(),
                        "main".into(),
                    ],
                )?;
                if guard.options.ipv6 {
                    guard.add_rule(
                        true,
                        vec![
                            "pref".into(),
                            PREF_SSH.to_string(),
                            "sport".into(),
                            port.to_string(),
                            "lookup".into(),
                            "main".into(),
                        ],
                    )?;
                }
            }
            guard.add_rule(
                false,
                vec![
                    "pref".into(),
                    PREF_VPN.to_string(),
                    "fwmark".into(),
                    TAILSCALE_MARK.into(),
                    "lookup".into(),
                    "main".into(),
                ],
            )?;
            if guard.options.ipv6 {
                guard.add_rule(
                    true,
                    vec![
                        "pref".into(),
                        PREF_VPN.to_string(),
                        "fwmark".into(),
                        TAILSCALE_MARK.into(),
                        "lookup".into(),
                        "main".into(),
                    ],
                )?;
            }
            let mark = format!("0x{:x}", guard.options.mark);
            guard.add_rule(
                false,
                vec![
                    "pref".into(),
                    PREF_MARK.to_string(),
                    "fwmark".into(),
                    mark.clone(),
                    "lookup".into(),
                    "main".into(),
                ],
            )?;
            if guard.options.ipv6 {
                guard.add_rule(
                    true,
                    vec![
                        "pref".into(),
                        PREF_MARK.to_string(),
                        "fwmark".into(),
                        mark,
                        "lookup".into(),
                        "main".into(),
                    ],
                )?;
            }
            // Application DNS must enter the TUN even when resolv.conf points
            // at the loopback systemd-resolved stub. UDP is answered by
            // tun2proxy's virtual DNS so later flows keep the original domain;
            // TCP DNS stays inside the signed proxy path. Our own DNS sockets
            // match PREF_MARK first and therefore stay on the physical network
            // without polluting domain answers with virtual 198.18/15 addresses.
            for protocol in ["udp", "tcp"] {
                guard.add_rule(
                    false,
                    vec![
                        "pref".into(),
                        PREF_DNS.to_string(),
                        "ipproto".into(),
                        protocol.into(),
                        "dport".into(),
                        "53".into(),
                        "lookup".into(),
                        guard.options.table.to_string(),
                    ],
                )?;
                if guard.options.ipv6 {
                    guard.add_rule(
                        true,
                        vec![
                            "pref".into(),
                            PREF_DNS.to_string(),
                            "ipproto".into(),
                            protocol.into(),
                            "dport".into(),
                            "53".into(),
                            "lookup".into(),
                            guard.options.table.to_string(),
                        ],
                    )?;
                }
            }
            guard.install_server_reply_bypass();
            // Catch-all is deliberately last: until this point normal routing
            // is untouched, even if any setup step fails.
            guard.add_rule(
                false,
                vec![
                    "pref".into(),
                    PREF_TUN.to_string(),
                    "lookup".into(),
                    guard.options.table.to_string(),
                ],
            )?;
            if guard.options.ipv6 {
                guard.add_rule(
                    true,
                    vec![
                        "pref".into(),
                        PREF_TUN.to_string(),
                        "lookup".into(),
                        guard.options.table.to_string(),
                    ],
                )?;
            }
            Ok(guard)
        }

        fn add_rule(&mut self, ipv6: bool, args: Vec<String>) -> Result<()> {
            let mut command = Vec::new();
            if ipv6 {
                command.push("-6".to_string());
            }
            command.extend(["rule".into(), "add".into()]);
            command.extend(args.iter().cloned());
            let refs = command.iter().map(String::as_str).collect::<Vec<_>>();
            run_ip(&refs)?;
            self.rules.push(Rule { ipv6, args });
            Ok(())
        }

        fn clear_stale_core(&self, _tun_name: &str) {
            for (ipv6, args) in self.core_rules() {
                delete_all_rules(ipv6, &args);
            }
            let table = self.options.table.to_string();
            let _ = run_ip(&["route", "flush", "table", &table]);
            let _ = run_ip(&["-6", "route", "flush", "table", &table]);
            self.remove_server_reply_bypass();
        }

        fn core_rules(&self) -> Vec<(bool, Vec<String>)> {
            let mark = format!("0x{:x}", self.options.mark);
            let mut result = Vec::new();
            for ipv6 in [false, true] {
                result.push((
                    ipv6,
                    vec![
                        "pref".into(),
                        PREF_TUN.to_string(),
                        "lookup".into(),
                        self.options.table.to_string(),
                    ],
                ));
                result.push((
                    ipv6,
                    vec![
                        "pref".into(),
                        PREF_MARK.to_string(),
                        "fwmark".into(),
                        mark.clone(),
                        "lookup".into(),
                        "main".into(),
                    ],
                ));
                result.push((
                    ipv6,
                    vec![
                        "pref".into(),
                        PREF_VPN.to_string(),
                        "fwmark".into(),
                        TAILSCALE_MARK.into(),
                        "lookup".into(),
                        "main".into(),
                    ],
                ));
                for port in SSH_PORTS {
                    result.push((
                        ipv6,
                        vec![
                            "pref".into(),
                            PREF_SSH.to_string(),
                            "sport".into(),
                            port.to_string(),
                            "lookup".into(),
                            "main".into(),
                        ],
                    ));
                }
                for protocol in ["udp", "tcp"] {
                    result.push((
                        ipv6,
                        vec![
                            "pref".into(),
                            PREF_DNS.to_string(),
                            "ipproto".into(),
                            protocol.into(),
                            "dport".into(),
                            "53".into(),
                            "lookup".into(),
                            self.options.table.to_string(),
                        ],
                    ));
                }
            }
            result
        }

        fn install_server_reply_bypass(&mut self) {
            for path in [
                "/proc/sys/net/ipv4/conf/all/rp_filter",
                "/proc/sys/net/ipv4/conf/default/rp_filter",
            ] {
                if let Ok(value) = fs::read_to_string(path) {
                    self.rp_filter.push((path.into(), value));
                    let _ = fs::write(path, "2\n");
                }
            }
            let mark = format!("0x{:x}", self.options.mark);
            for binary in ["iptables", "ip6tables"] {
                let _ = run_optional(
                    binary,
                    &[
                        "-t",
                        "mangle",
                        "-A",
                        "PREROUTING",
                        "-m",
                        "conntrack",
                        "--ctstate",
                        "NEW",
                        "-j",
                        "CONNMARK",
                        "--set-mark",
                        &mark,
                    ],
                );
                let _ = run_optional(
                    binary,
                    &[
                        "-t",
                        "mangle",
                        "-A",
                        "OUTPUT",
                        "-m",
                        "connmark",
                        "--mark",
                        &mark,
                        "-j",
                        "CONNMARK",
                        "--restore-mark",
                    ],
                );
            }
        }

        fn remove_server_reply_bypass(&self) {
            let mark = format!("0x{:x}", self.options.mark);
            for binary in ["iptables", "ip6tables"] {
                for _ in 0..16 {
                    if run_optional(
                        binary,
                        &[
                            "-t",
                            "mangle",
                            "-D",
                            "PREROUTING",
                            "-m",
                            "conntrack",
                            "--ctstate",
                            "NEW",
                            "-j",
                            "CONNMARK",
                            "--set-mark",
                            &mark,
                        ],
                    )
                    .is_err()
                    {
                        break;
                    }
                }
                for _ in 0..16 {
                    if run_optional(
                        binary,
                        &[
                            "-t",
                            "mangle",
                            "-D",
                            "OUTPUT",
                            "-m",
                            "connmark",
                            "--mark",
                            &mark,
                            "-j",
                            "CONNMARK",
                            "--restore-mark",
                        ],
                    )
                    .is_err()
                    {
                        break;
                    }
                }
            }
        }

        pub fn restore(&mut self) {
            if self.restored {
                return;
            }
            self.restored = true;
            // Reverse installation order: stop new capture first.
            for rule in self.rules.iter().rev() {
                let _ = delete_rule(rule.ipv6, &rule.args);
            }
            self.remove_server_reply_bypass();
            for (path, value) in self.rp_filter.drain(..) {
                let _ = fs::write(path, value);
            }
            let table = self.options.table.to_string();
            let _ = run_ip(&["route", "flush", "table", &table]);
            let _ = run_ip(&["-6", "route", "flush", "table", &table]);
        }
    }

    impl Drop for RouteGuard {
        fn drop(&mut self) {
            self.restore();
        }
    }

    fn delete_rule(ipv6: bool, args: &[String]) -> Result<()> {
        let mut command = Vec::new();
        if ipv6 {
            command.push("-6".to_string());
        }
        command.extend(["rule".into(), "del".into()]);
        command.extend(args.iter().cloned());
        let refs = command.iter().map(String::as_str).collect::<Vec<_>>();
        run_ip(&refs)
    }

    fn delete_all_rules(ipv6: bool, args: &[String]) {
        for _ in 0..64 {
            if delete_rule(ipv6, args).is_err() {
                break;
            }
        }
    }

    fn run_ip(args: &[&str]) -> Result<()> {
        run_command("ip", args)
    }

    fn run_optional(binary: &str, args: &[&str]) -> Result<()> {
        run_command(binary, args)
    }

    fn run_command(binary: &str, args: &[&str]) -> Result<()> {
        let output = Command::new(binary)
            .args(args)
            .output()
            .with_context(|| format!("运行 {binary} 失败"))?;
        if !output.status.success() {
            let detail = if output.stderr.is_empty() {
                &output.stdout
            } else {
                &output.stderr
            };
            bail!(
                "{} {} 失败：{}",
                binary,
                args.join(" "),
                String::from_utf8_lossy(detail).trim()
            );
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        #[test]
        fn validates_tun_options_and_normalizes_bypasses() {
            let options = Options::default();
            options.validate().unwrap();
            assert_eq!(normalize_cidr("1.1.1.1").unwrap(), "1.1.1.1/32");
            assert_eq!(normalize_cidr("2001:db8::1").unwrap(), "2001:db8::1/128");
            assert!(normalize_cidr("1.1.1.1/33").is_err());
            assert!(Options {
                name: "bad/name".into(),
                ..options
            }
            .validate()
            .is_err());
        }

        #[test]
        fn parses_established_ipv4_and_ipv6_ssh_peers() {
            let v4 = " 0: 0100007F:0016 04030201:C001 01 00000000:00000000 00:00000000 00000000";
            assert_eq!(
                parse_proc_tcp_line(v4, false),
                Some("1.2.3.4".parse().unwrap())
            );
            let v6 = " 0: 00000000000000000000000001000000:08AE 00000000000000000000000004030201:C001 01 0:0 00:0 0";
            assert_eq!(
                parse_proc_tcp_line(v6, true),
                Some("::102:304".parse().unwrap())
            );
            assert!(parse_proc_tcp_line(&v4.replace(":0016", ":01BB"), false).is_none());
        }

        #[test]
        fn builds_virtual_dns_stack_arguments() {
            let args = stack_args("127.0.0.1:7388".parse().unwrap(), &Options::default()).unwrap();
            assert_eq!(args.dns, tun2proxy::ArgDns::Virtual);
            assert!(args.ipv6_enabled);
            assert_eq!(args.tcp_mss, Some(1360));
            assert_eq!(args.max_sessions, 512);
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn linux_namespace_moves_real_tcp_and_udp_through_tun() {
            if std::env::var_os("RF_TEST_TUN_ROOT").is_none() {
                return;
            }
            assert!(Command::new("ip")
                .args(["link", "set", "lo", "up"])
                .status()
                .unwrap()
                .success());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let proxy = listener.local_addr().unwrap();
            let fake = tokio::spawn(async move {
                for _ in 0..2 {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    tokio::spawn(async move {
                        let mut hello = [0u8; 2];
                        stream.read_exact(&mut hello).await.unwrap();
                        let mut methods = vec![0u8; hello[1] as usize];
                        stream.read_exact(&mut methods).await.unwrap();
                        stream.write_all(&[5, 0]).await.unwrap();
                        let mut request = [0u8; 4];
                        stream.read_exact(&mut request).await.unwrap();
                        match request[3] {
                            1 => {
                                let mut rest = [0u8; 6];
                                stream.read_exact(&mut rest).await.unwrap();
                            }
                            4 => {
                                let mut rest = [0u8; 18];
                                stream.read_exact(&mut rest).await.unwrap();
                            }
                            3 => {
                                let length = stream.read_u8().await.unwrap() as usize;
                                let mut rest = vec![0u8; length + 2];
                                stream.read_exact(&mut rest).await.unwrap();
                            }
                            _ => panic!("unexpected SOCKS address type"),
                        }
                        if request[1] == 1 {
                            stream
                                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 0])
                                .await
                                .unwrap();
                            let mut payload = [0u8; 64];
                            let length = stream.read(&mut payload).await.unwrap();
                            stream.write_all(&payload[..length]).await.unwrap();
                        } else {
                            let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                            let address = udp.local_addr().unwrap();
                            let mut reply = vec![5, 0, 0, 1, 127, 0, 0, 1];
                            reply.extend_from_slice(&address.port().to_be_bytes());
                            stream.write_all(&reply).await.unwrap();
                            let mut frame = vec![0u8; 2048];
                            let (length, peer) = udp.recv_from(&mut frame).await.unwrap();
                            udp.send_to(&frame[..length], peer).await.unwrap();
                        }
                    });
                }
            });

            let options = Options {
                name: "rf-e2e0".into(),
                ipv6: false,
                ..Options::default()
            };
            let tun = open_device(&options).unwrap();
            let tun_name = tun_name(&tun).unwrap();
            let args = stack_args(proxy, &options).unwrap();
            let cancellation = tun2proxy::CancellationToken::new();
            let stack_cancel = cancellation.clone();
            let mtu = options.mtu;
            let stack =
                tokio::spawn(
                    async move { tun2proxy::run(tun, mtu, args, stack_cancel).await.unwrap() },
                );
            tokio::task::yield_now().await;
            let mut routes =
                RouteGuard::install(options, &tun_name, vec!["127.0.0.0/8".into()]).unwrap();

            let tcp = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::TcpStream::connect("203.0.113.10:8080"),
            )
            .await
            .unwrap()
            .unwrap();
            let (mut reader, mut writer) = tcp.into_split();
            writer.write_all(b"rf-tun-tcp").await.unwrap();
            let mut echoed = [0u8; 10];
            tokio::time::timeout(Duration::from_secs(5), reader.read_exact(&mut echoed))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&echoed, b"rf-tun-tcp");

            let udp = tokio::net::UdpSocket::bind("0.0.0.0:0").await.unwrap();
            udp.connect("203.0.113.10:5353").await.unwrap();
            udp.send(b"rf-tun-udp").await.unwrap();
            let mut echoed = [0u8; 10];
            let length = tokio::time::timeout(Duration::from_secs(5), udp.recv(&mut echoed))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&echoed[..length], b"rf-tun-udp");

            routes.restore();
            cancellation.cancel();
            let _ = tokio::time::timeout(Duration::from_secs(5), stack).await;
            let _ = tokio::time::timeout(Duration::from_secs(5), fake).await;
            let rules = Command::new("ip").args(["rule", "show"]).output().unwrap();
            let rules = String::from_utf8_lossy(&rules.stdout);
            assert!(!rules.contains(&PREF_TUN.to_string()));
        }
    }
}

#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(not(target_os = "linux"))]
#[derive(Debug, Clone)]
pub struct Options {
    pub name: String,
    pub mtu: u16,
    pub mark: u32,
    pub table: u32,
    pub ipv6: bool,
    pub bypass: Vec<String>,
    pub dns_servers: Vec<std::net::IpAddr>,
    pub max_sessions: usize,
    pub deadman_seconds: u64,
}

#[cfg(not(target_os = "linux"))]
impl Default for Options {
    fn default() -> Self {
        Self {
            name: "rf-tun0".into(),
            mtu: 1400,
            mark: 0x52f1,
            table: 7388,
            ipv6: true,
            bypass: Vec::new(),
            dns_servers: Vec::new(),
            max_sessions: 512,
            deadman_seconds: 300,
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub struct MarkedResolver;
