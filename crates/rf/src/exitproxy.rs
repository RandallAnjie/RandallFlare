//! TLS-encrypted split-routing egress and the user-side local proxy.
//!
//! Exit nodes expose SOCKS5 only inside TLS. The username is the signed device
//! resource name and the password is its one-time-displayed bearer token. The
//! exit independently re-evaluates the signed rules and resolves DNS before it
//! dials, so a modified client cannot turn the service into an open proxy or
//! use DNS rebinding to reach loopback, LAN, metadata, or overlay addresses.

use crate::exit::{self, Decision, DevicePrincipal, ExitRuleSpec};
use crate::node::Node;
use anyhow::{bail, Context, Result};
use rustls::pki_types::ServerName;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{RwLock, Semaphore};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use zeroize::Zeroizing;

const SOCKS_VERSION: u8 = 5;
const AUTH_NONE: u8 = 0;
const AUTH_PASSWORD: u8 = 2;
const AUTH_REJECT: u8 = 0xff;
const CMD_CONNECT: u8 = 1;
const CMD_UDP_ASSOCIATE: u8 = 3;
const ATYP_V4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_V6: u8 = 4;
const REP_OK: u8 = 0;
const REP_FAILURE: u8 = 1;
const REP_FORBIDDEN: u8 = 2;
const REP_HOST_UNREACHABLE: u8 = 4;
const REP_COMMAND_UNSUPPORTED: u8 = 7;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HTTP_HEADER: usize = 32 * 1024;
const MAX_UDP_PAYLOAD: usize = 65_507;
const MAX_SOCKS_UDP_FRAME: usize = MAX_UDP_PAYLOAD + 262;
const UDP_ASSOCIATION_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceExit {
    pub node_id: String,
    pub label: String,
    pub endpoint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRule {
    pub name: String,
    pub version: u64,
    pub digest: String,
    pub spec: ExitRuleSpec,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceConfig {
    pub schema: u8,
    pub cluster_id: String,
    pub device: String,
    pub label: String,
    pub rules: Vec<DeviceRule>,
    pub exits: Vec<DeviceExit>,
    pub refresh_after_seconds: u64,
}

pub fn config_for_device(node: &Node, principal: &DevicePrincipal) -> DeviceConfig {
    let rules = exit::rules_for_device(node, &principal.spec)
        .into_iter()
        .map(|(view, spec)| DeviceRule {
            name: view.resource.name,
            version: view.resource.version,
            digest: view.digest,
            spec,
        })
        .collect::<Vec<_>>();
    let mut exits = Vec::new();
    if node.cfg.exit.enabled {
        if let Some(endpoint) = &node.cfg.exit.advertise {
            exits.push(DeviceExit {
                node_id: node.id_hex(),
                label: node.cfg.label.clone(),
                endpoint: endpoint.clone(),
            });
        }
    }
    for (node_id, peer) in node.peers() {
        if !peer.capabilities.contains("exit") {
            continue;
        }
        if let Some(endpoint) = peer.exit_endpoint {
            exits.push(DeviceExit {
                node_id,
                label: peer.label,
                endpoint,
            });
        }
    }
    exits.sort_by(|left, right| left.node_id.cmp(&right.node_id));
    exits.dedup_by(|left, right| left.node_id == right.node_id);
    DeviceConfig {
        schema: 1,
        cluster_id: node.cfg.cluster_id.clone(),
        device: principal.name.clone(),
        label: principal.spec.label.clone(),
        rules,
        exits,
        refresh_after_seconds: 30,
    }
}

pub async fn serve(node: Arc<Node>) -> Result<()> {
    if !node.cfg.exit.enabled {
        return Ok(());
    }
    let listen = node
        .cfg
        .exit
        .listen
        .context("exit.listen is required when exit is enabled")?;
    let store = crate::tls::spawn_store(node.cfg.data_dir.join("certs"))?;
    let acceptor = TlsAcceptor::from(crate::tls::server_config(store));
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("监听设备出口 {listen}"))?;
    let sessions = Arc::new(Semaphore::new(node.cfg.exit.max_sessions as usize));
    tracing::info!(
        listen = %listen,
        advertise = node.cfg.exit.advertise.as_deref().unwrap_or(""),
        "TLS 设备出口已启动"
    );
    tokio::spawn(async move {
        loop {
            let (stream, remote) = match listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    tracing::warn!("设备出口 accept 失败：{error}");
                    continue;
                }
            };
            let Ok(permit) = sessions.clone().try_acquire_owned() else {
                drop(stream);
                continue;
            };
            let acceptor = acceptor.clone();
            let node = node.clone();
            tokio::spawn(async move {
                let _permit = permit;
                let result = tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await;
                let mut tls = match result {
                    Ok(Ok(tls)) => tls,
                    Ok(Err(error)) => {
                        tracing::debug!(%remote, "设备出口 TLS 握手失败：{error}");
                        return;
                    }
                    Err(_) => return,
                };
                if let Err(error) = serve_egress(&node, &mut tls).await {
                    tracing::debug!(%remote, "设备出口会话结束：{error:#}");
                }
            });
        }
    });
    Ok(())
}

async fn serve_egress<S>(node: &Node, stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (principal, request) = server_socks_handshake(node, stream).await?;
    let EgressRequest::Connect { host, port } = request else {
        socks_reply(stream, REP_OK).await?;
        return serve_udp_tunnel(node, &principal, stream).await;
    };
    let candidates = match public_candidates(&host, port).await {
        Ok(candidates) => candidates,
        Err(error) => {
            socks_reply(stream, REP_FORBIDDEN).await?;
            return Err(error);
        }
    };
    let mut allowed = Vec::new();
    for address in candidates {
        let decision = match device_decision(node, &principal, &host, Some(address.ip())) {
            Ok(decision) => decision,
            Err(error) => {
                socks_reply(stream, REP_FORBIDDEN).await?;
                return Err(error);
            }
        };
        if decision == Decision::Node(node.id_hex()) || decision == Decision::Nearest {
            allowed.push(address);
        }
    }
    if allowed.is_empty() {
        socks_reply(stream, REP_FORBIDDEN).await?;
        bail!("设备规则不允许从此节点转发目标");
    }
    let timeout = Duration::from_secs(node.cfg.exit.connect_timeout_seconds);
    let mut upstream = match connect_candidates(&allowed, timeout).await {
        Ok(stream) => stream,
        Err(error) => {
            socks_reply(stream, REP_HOST_UNREACHABLE).await?;
            return Err(error);
        }
    };
    socks_reply(stream, REP_OK).await?;
    let _ = tokio::io::copy_bidirectional(stream, &mut upstream).await?;
    Ok(())
}

enum EgressRequest {
    Connect { host: String, port: u16 },
    UdpAssociate,
}

fn device_decision(
    node: &Node,
    principal: &DevicePrincipal,
    host: &str,
    ip: Option<IpAddr>,
) -> Result<Decision> {
    let rules = exit::rules_for_device(node, &principal.spec);
    if rules.len() != principal.spec.allowed_rules.len() {
        return Ok(Decision::Reject);
    }
    for (_, spec) in rules {
        if let Some(decision) = exit::classify(&spec, host, ip)? {
            return Ok(decision);
        }
    }
    Ok(Decision::Direct)
}

async fn server_socks_handshake<S>(
    node: &Node,
    stream: &mut S,
) -> Result<(DevicePrincipal, EgressRequest)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION || header[1] == 0 || header[1] > 16 {
        bail!("SOCKS 协商无效");
    }
    let mut methods = vec![0u8; header[1] as usize];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&AUTH_PASSWORD) {
        stream.write_all(&[SOCKS_VERSION, AUTH_REJECT]).await?;
        bail!("设备出口必须使用用户名/令牌认证");
    }
    stream.write_all(&[SOCKS_VERSION, AUTH_PASSWORD]).await?;
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).await?;
    if auth[0] != 1 || auth[1] == 0 {
        bail!("设备认证帧无效");
    }
    let mut name = vec![0u8; auth[1] as usize];
    stream.read_exact(&mut name).await?;
    let token_len = stream.read_u8().await? as usize;
    if token_len == 0 {
        bail!("设备令牌为空");
    }
    let mut token = Zeroizing::new(vec![0u8; token_len]);
    stream.read_exact(&mut token).await?;
    let name = std::str::from_utf8(&name).unwrap_or_default();
    let token = std::str::from_utf8(&token).unwrap_or_default();
    let principal = exit::resolve_device(node, name, token);
    stream
        .write_all(&[1, u8::from(principal.is_none())])
        .await?;
    let principal = principal.context("设备令牌无效、过期、已暂停或已撤销")?;

    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != SOCKS_VERSION {
        socks_reply(stream, REP_FAILURE).await?;
        bail!("设备出口 SOCKS 版本无效");
    }
    if !matches!(request[1], CMD_CONNECT | CMD_UDP_ASSOCIATE) {
        socks_reply(stream, REP_COMMAND_UNSUPPORTED).await?;
        bail!("设备出口只支持 SOCKS CONNECT 与 UDP ASSOCIATE");
    }
    let host = read_socks_host(stream, request[3]).await?;
    let port = stream.read_u16().await?;
    if request[1] == CMD_CONNECT && (host.is_empty() || port == 0) {
        socks_reply(stream, REP_FAILURE).await?;
        bail!("出口目标无效");
    }
    Ok((
        principal,
        if request[1] == CMD_CONNECT {
            EgressRequest::Connect { host, port }
        } else {
            EgressRequest::UdpAssociate
        },
    ))
}

async fn read_socks_host<S>(stream: &mut S, atyp: u8) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    match atyp {
        ATYP_V4 => {
            let mut raw = [0u8; 4];
            stream.read_exact(&mut raw).await?;
            Ok(std::net::Ipv4Addr::from(raw).to_string())
        }
        ATYP_V6 => {
            let mut raw = [0u8; 16];
            stream.read_exact(&mut raw).await?;
            Ok(std::net::Ipv6Addr::from(raw).to_string())
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                bail!("SOCKS 域名为空");
            }
            let mut raw = vec![0u8; len];
            stream.read_exact(&mut raw).await?;
            let host = std::str::from_utf8(&raw).context("SOCKS 域名不是 UTF-8")?;
            Ok(host.trim_end_matches('.').to_ascii_lowercase())
        }
        _ => bail!("SOCKS 地址类型不受支持"),
    }
}

async fn socks_reply<S>(stream: &mut S, status: u8) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream
        .write_all(&[SOCKS_VERSION, status, 0, ATYP_V4, 0, 0, 0, 0, 0, 0])
        .await?;
    Ok(())
}

async fn socks_reply_address<S>(stream: &mut S, status: u8, address: SocketAddr) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut response = vec![SOCKS_VERSION, status, 0];
    match address.ip() {
        IpAddr::V4(ip) => {
            response.push(ATYP_V4);
            response.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            response.push(ATYP_V6);
            response.extend_from_slice(&ip.octets());
        }
    }
    response.extend_from_slice(&address.port().to_be_bytes());
    stream.write_all(&response).await?;
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SocksUdpPacket {
    host: String,
    port: u16,
    payload: Vec<u8>,
}

fn parse_socks_udp_packet(frame: &[u8]) -> Result<SocksUdpPacket> {
    if frame.len() > MAX_SOCKS_UDP_FRAME || frame.len() < 7 || frame[..2] != [0, 0] {
        bail!("SOCKS UDP 数据帧无效或过大");
    }
    if frame[2] != 0 {
        bail!("SOCKS UDP 分片不受支持；请由 IP 层完成分片");
    }
    let mut offset = 4usize;
    let host = match frame[3] {
        ATYP_V4 => {
            let raw: [u8; 4] = frame
                .get(offset..offset + 4)
                .context("SOCKS UDP IPv4 地址不完整")?
                .try_into()
                .unwrap();
            offset += 4;
            std::net::Ipv4Addr::from(raw).to_string()
        }
        ATYP_V6 => {
            let raw: [u8; 16] = frame
                .get(offset..offset + 16)
                .context("SOCKS UDP IPv6 地址不完整")?
                .try_into()
                .unwrap();
            offset += 16;
            std::net::Ipv6Addr::from(raw).to_string()
        }
        ATYP_DOMAIN => {
            let length = usize::from(*frame.get(offset).context("SOCKS UDP 域名长度缺失")?);
            offset += 1;
            if length == 0 {
                bail!("SOCKS UDP 域名为空");
            }
            let raw = frame
                .get(offset..offset + length)
                .context("SOCKS UDP 域名不完整")?;
            offset += length;
            std::str::from_utf8(raw)
                .context("SOCKS UDP 域名不是 UTF-8")?
                .trim_end_matches('.')
                .to_ascii_lowercase()
        }
        _ => bail!("SOCKS UDP 地址类型不受支持"),
    };
    let port = u16::from_be_bytes(
        frame
            .get(offset..offset + 2)
            .context("SOCKS UDP 端口缺失")?
            .try_into()
            .unwrap(),
    );
    offset += 2;
    if port == 0 {
        bail!("SOCKS UDP 目标端口不得为 0");
    }
    let payload = frame.get(offset..).context("SOCKS UDP 载荷缺失")?.to_vec();
    if payload.len() > MAX_UDP_PAYLOAD {
        bail!("SOCKS UDP 载荷超过协议上限");
    }
    Ok(SocksUdpPacket {
        host,
        port,
        payload,
    })
}

fn encode_socks_udp_packet(packet: &SocksUdpPacket) -> Result<Vec<u8>> {
    if packet.port == 0 || packet.payload.len() > MAX_UDP_PAYLOAD {
        bail!("SOCKS UDP 响应目标或载荷无效");
    }
    let mut frame = vec![0, 0, 0];
    if let Ok(ip) = packet.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip) => {
                frame.push(ATYP_V4);
                frame.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                frame.push(ATYP_V6);
                frame.extend_from_slice(&ip.octets());
            }
        }
    } else {
        if packet.host.is_empty() || packet.host.len() > u8::MAX as usize {
            bail!("SOCKS UDP 域名长度无效");
        }
        frame.push(ATYP_DOMAIN);
        frame.push(packet.host.len() as u8);
        frame.extend_from_slice(packet.host.as_bytes());
    }
    frame.extend_from_slice(&packet.port.to_be_bytes());
    frame.extend_from_slice(&packet.payload);
    if frame.len() > MAX_SOCKS_UDP_FRAME {
        bail!("SOCKS UDP 数据帧超过上限");
    }
    Ok(frame)
}

async fn udp_exchange(
    addresses: &[SocketAddr],
    payload: &[u8],
    timeout: Duration,
) -> Result<Vec<u8>> {
    let mut errors = Vec::new();
    for address in addresses {
        let bind = if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = match UdpSocket::bind(bind).await {
            Ok(socket) => socket,
            Err(error) => {
                errors.push(format!("{address}: {error}"));
                continue;
            }
        };
        if let Err(error) = socket.connect(address).await {
            errors.push(format!("{address}: {error}"));
            continue;
        }
        if let Err(error) = socket.send(payload).await {
            errors.push(format!("{address}: {error}"));
            continue;
        }
        let mut response = vec![0u8; MAX_UDP_PAYLOAD];
        match tokio::time::timeout(timeout, socket.recv(&mut response)).await {
            Ok(Ok(length)) => {
                response.truncate(length);
                return Ok(response);
            }
            Ok(Err(error)) => errors.push(format!("{address}: {error}")),
            Err(_) => errors.push(format!("{address}: 超时")),
        }
    }
    bail!("所有 UDP 目标均失败：{}", errors.join("；"))
}

async fn serve_udp_tunnel<S>(node: &Node, principal: &DevicePrincipal, stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    loop {
        let length = match tokio::time::timeout(UDP_ASSOCIATION_IDLE_TIMEOUT, stream.read_u32())
            .await
        {
            Ok(Ok(length)) => length as usize,
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Ok(Err(error)) => return Err(error.into()),
            Err(_) => return Ok(()),
        };
        if length == 0 || length > MAX_SOCKS_UDP_FRAME {
            bail!("出口 UDP 隧道帧长度无效");
        }
        let mut frame = vec![0u8; length];
        stream.read_exact(&mut frame).await?;
        let response = async {
            let packet = parse_socks_udp_packet(&frame)?;
            let candidates = public_candidates(&packet.host, packet.port).await?;
            let local_node_id = node.id_hex();
            let allowed = candidates
                .into_iter()
                .filter(|address| {
                    match device_decision(node, principal, &packet.host, Some(address.ip())) {
                        Ok(Decision::Nearest) => true,
                        Ok(Decision::Node(id)) => id == local_node_id,
                        _ => false,
                    }
                })
                .collect::<Vec<_>>();
            if allowed.is_empty() {
                bail!("设备规则不允许从此节点转发 UDP 目标");
            }
            let payload = udp_exchange(
                &allowed,
                &packet.payload,
                Duration::from_secs(node.cfg.exit.connect_timeout_seconds),
            )
            .await?;
            encode_socks_udp_packet(&SocksUdpPacket { payload, ..packet })
        }
        .await;
        match response {
            Ok(frame) => {
                stream.write_u8(REP_OK).await?;
                stream.write_u32(frame.len() as u32).await?;
                stream.write_all(&frame).await?;
            }
            Err(error) => {
                tracing::debug!(device = %principal.name, "出口 UDP 数据报被拒绝：{error:#}");
                stream.write_u8(REP_FORBIDDEN).await?;
                stream.write_u32(0).await?;
            }
        }
        stream.flush().await?;
    }
}

async fn public_candidates(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("解析出口目标 {host}"))?;
    let mut safe = addresses
        .filter(|address| public_egress_ip(address.ip()))
        .collect::<Vec<_>>();
    safe.sort();
    safe.dedup();
    if safe.is_empty() {
        bail!("出口目标解析结果全部属于非公网或保留地址");
    }
    Ok(safe)
}

async fn direct_candidates(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addresses = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("解析直连目标 {host}"))?;
    let mut safe = addresses
        .filter(|address| safe_direct_ip(address.ip()))
        .collect::<Vec<_>>();
    safe.sort();
    safe.dedup();
    if safe.is_empty() {
        bail!("直连目标解析结果全部不安全");
    }
    Ok(safe)
}

fn safe_direct_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let octets = ip.octets();
            !ip.is_unspecified() && !ip.is_multicast() && !(octets[0] == 169 && octets[1] == 254)
        }
        IpAddr::V6(ip) => {
            let first = ip.segments()[0];
            !ip.is_unspecified() && !ip.is_multicast() && first & 0xffc0 != 0xfe80
        }
    }
}

pub fn public_egress_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !(a == 0
                || a == 10
                || a == 127
                || (a == 100 && b & 0xc0 == 64)
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || (a == 192 && b == 0)
                || (a == 192 && b == 88 && c == 99)
                || (a == 192 && b == 175 && c == 48)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || a >= 224)
        }
        IpAddr::V6(ip) => {
            if let Some(mapped) = ip.to_ipv4_mapped() {
                return public_egress_ip(IpAddr::V4(mapped));
            }
            let segments = ip.segments();
            if segments[..6].iter().all(|segment| *segment == 0) {
                let mapped = std::net::Ipv4Addr::new(
                    (segments[6] >> 8) as u8,
                    segments[6] as u8,
                    (segments[7] >> 8) as u8,
                    segments[7] as u8,
                );
                return public_egress_ip(IpAddr::V4(mapped));
            }
            !ip.is_unspecified()
                && !ip.is_loopback()
                && !ip.is_multicast()
                // IPv4/IPv6 translation prefixes can otherwise encode a
                // private IPv4 target that passed the IPv6-only checks.
                && !(segments[0] == 0x0064
                    && segments[1] == 0xff9b
                    && (segments[2] == 0x0001
                        || segments[2..6].iter().all(|segment| *segment == 0)))
                // Discard-only and IETF protocol-assignment space.
                && !(segments[0] == 0x0100
                    && segments[1..4].iter().all(|segment| *segment == 0))
                && !(segments[0] == 0x2001 && segments[1] < 0x0200)
                && segments[0] != 0x2002
                && segments[0] & 0xfe00 != 0xfc00
                && segments[0] & 0xffc0 != 0xfe80
                && segments[0] & 0xffc0 != 0xfec0
                && !(segments[0] == 0x2001 && segments[1] == 0x0db8)
                && segments[0] & 0xfff0 != 0x3ff0
        }
    }
}

async fn connect_candidates(addresses: &[SocketAddr], timeout: Duration) -> Result<TcpStream> {
    let mut errors = Vec::new();
    for address in addresses {
        match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => errors.push(format!("{address}: {error}")),
            Err(_) => errors.push(format!("{address}: 超时")),
        }
    }
    bail!("所有目标地址连接失败：{}", errors.join("；"))
}

#[derive(Clone)]
struct ClientState {
    control: Arc<str>,
    device: Arc<str>,
    token: Arc<Zeroizing<String>>,
    config: Arc<RwLock<DeviceConfig>>,
    tls: Arc<rustls::ClientConfig>,
}

pub async fn run_device_proxy(
    control: String,
    device: String,
    token: String,
    listen: SocketAddr,
) -> Result<()> {
    if !listen.ip().is_loopback() {
        bail!("设备本地代理只能监听回环地址；拒绝暴露无认证入口");
    }
    let token = Arc::new(Zeroizing::new(token));
    let initial = fetch_device_config(&control, &device, token.as_str()).await?;
    if initial.device != device {
        bail!("控制节点返回了其他设备的配置");
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let tls = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
    );
    let state = ClientState {
        control: control.into(),
        device: device.into(),
        token,
        config: Arc::new(RwLock::new(initial)),
        tls,
    };
    spawn_config_refresh(state.clone());
    let listener = TcpListener::bind(listen)
        .await
        .with_context(|| format!("监听设备本地代理 {listen}"))?;
    tracing::info!(%listen, device = %state.device, "设备分流代理已启动");
    loop {
        let (stream, remote) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            if let Err(error) = handle_local(state, stream).await {
                tracing::debug!(%remote, "设备本地代理会话结束：{error:#}");
            }
        });
    }
}

fn spawn_config_refresh(state: ClientState) {
    tokio::spawn(async move {
        loop {
            let delay = state
                .config
                .read()
                .await
                .refresh_after_seconds
                .clamp(10, 300);
            tokio::time::sleep(Duration::from_secs(delay)).await;
            match fetch_device_config(&state.control, &state.device, state.token.as_str()).await {
                Ok(config) if config.device == *state.device => {
                    *state.config.write().await = config;
                }
                Ok(_) => tracing::warn!("设备配置身份不一致，保留上一份签名配置"),
                Err(error) => tracing::warn!("刷新设备配置失败，保留上一份配置：{error:#}"),
            }
        }
    });
}

async fn fetch_device_config(control: &str, device: &str, token: &str) -> Result<DeviceConfig> {
    let url = format!(
        "{}/device/v1/config/{}",
        control.trim_end_matches('/'),
        percent_encoding::utf8_percent_encode(device, percent_encoding::NON_ALPHANUMERIC)
    );
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()?
        .get(url)
        .bearer_auth(token)
        .send()
        .await?
        .error_for_status()?;
    Ok(response.json().await?)
}

enum LocalRequest {
    Socks {
        host: String,
        port: u16,
    },
    SocksUdp {
        requested_port: u16,
    },
    HttpConnect {
        host: String,
        port: u16,
    },
    HttpPlain {
        host: String,
        port: u16,
        initial: Vec<u8>,
    },
}

async fn handle_local(state: ClientState, mut downstream: TcpStream) -> Result<()> {
    let first = downstream.read_u8().await?;
    let request = if first == SOCKS_VERSION {
        local_socks_request(&mut downstream).await?
    } else {
        local_http_request(&mut downstream, first).await?
    };
    if let LocalRequest::SocksUdp { requested_port } = &request {
        return serve_local_udp_association(state, downstream, *requested_port).await;
    }
    let (host, port) = match &request {
        LocalRequest::Socks { host, port }
        | LocalRequest::HttpConnect { host, port }
        | LocalRequest::HttpPlain { host, port, .. } => (host.clone(), *port),
        LocalRequest::SocksUdp { .. } => unreachable!(),
    };
    let config = state.config.read().await.clone();
    let resolved = direct_candidates(&host, port).await.ok();
    let ip = resolved
        .as_ref()
        .and_then(|addresses| addresses.first())
        .map(SocketAddr::ip);
    let decision = classify_config(&config, &host, ip)?;
    let upstream: Result<Box<dyn AsyncStream>> = match decision {
        Decision::Reject => {
            reject_local(&mut downstream, &request).await?;
            bail!("目标被出口规则拒绝");
        }
        Decision::Direct => {
            let addresses = resolved.context("直连目标无法解析");
            match addresses {
                Ok(addresses) => connect_candidates(&addresses, Duration::from_secs(15))
                    .await
                    .map(|stream| Box::new(stream) as Box<dyn AsyncStream>),
                Err(error) => Err(error),
            }
        }
        Decision::Node(node_id) => {
            let exit = config
                .exits
                .iter()
                .find(|exit| exit.node_id == node_id)
                .cloned()
                .with_context(|| format!("指定出口节点 {node_id} 当前不可达"));
            match exit {
                Ok(exit) => connect_exit(&state, &exit, &host, port)
                    .await
                    .map(|stream| Box::new(stream) as Box<dyn AsyncStream>),
                Err(error) => Err(error),
            }
        }
        Decision::Nearest => match nearest_exit(&config.exits).await {
            Ok(exit) => connect_exit(&state, &exit, &host, port)
                .await
                .map(|stream| Box::new(stream) as Box<dyn AsyncStream>),
            Err(error) => Err(error),
        },
    };
    let mut upstream = match upstream {
        Ok(upstream) => upstream,
        Err(error) => {
            fail_local(&mut downstream, &request).await?;
            return Err(error);
        }
    };
    accept_local(&mut downstream, &request).await?;
    if let LocalRequest::HttpPlain { initial, .. } = &request {
        upstream.write_all(initial).await?;
    }
    let _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await?;
    Ok(())
}

trait AsyncStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T> AsyncStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

fn classify_config(config: &DeviceConfig, host: &str, ip: Option<IpAddr>) -> Result<Decision> {
    if config.rules.is_empty() {
        return Ok(Decision::Reject);
    }
    for rule in &config.rules {
        if let Some(decision) = exit::classify(&rule.spec, host, ip)? {
            return Ok(decision);
        }
    }
    Ok(Decision::Direct)
}

async fn local_socks_request(stream: &mut TcpStream) -> Result<LocalRequest> {
    let method_count = stream.read_u8().await? as usize;
    if method_count == 0 || method_count > 16 {
        bail!("SOCKS method 列表无效");
    }
    let mut methods = vec![0u8; method_count];
    stream.read_exact(&mut methods).await?;
    if !methods.contains(&AUTH_NONE) {
        stream.write_all(&[SOCKS_VERSION, AUTH_REJECT]).await?;
        bail!("本地 SOCKS 入口只接受无认证方法");
    }
    stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await?;
    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    if request[0] != SOCKS_VERSION {
        socks_reply(stream, REP_FAILURE).await?;
        bail!("本地 SOCKS 版本无效");
    }
    if !matches!(request[1], CMD_CONNECT | CMD_UDP_ASSOCIATE) {
        socks_reply(stream, REP_COMMAND_UNSUPPORTED).await?;
        bail!("本地 SOCKS 入口只支持 CONNECT 与 UDP ASSOCIATE");
    }
    let host = read_socks_host(stream, request[3]).await?;
    let port = stream.read_u16().await?;
    if request[1] == CMD_UDP_ASSOCIATE {
        Ok(LocalRequest::SocksUdp {
            requested_port: port,
        })
    } else if host.is_empty() || port == 0 {
        socks_reply(stream, REP_FAILURE).await?;
        bail!("本地 SOCKS 目标无效");
    } else {
        Ok(LocalRequest::Socks { host, port })
    }
}

async fn local_http_request(stream: &mut TcpStream, first: u8) -> Result<LocalRequest> {
    let mut header = vec![first];
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= MAX_HTTP_HEADER {
            bail!("HTTP 代理请求头过大");
        }
        header.push(stream.read_u8().await?);
    }
    let text = std::str::from_utf8(&header).context("HTTP 代理请求头不是 UTF-8")?;
    let first_line = text.lines().next().context("HTTP 请求行缺失")?;
    let mut fields = first_line.split_whitespace();
    let method = fields.next().unwrap_or_default();
    let target = fields.next().unwrap_or_default();
    let version = fields.next().unwrap_or("HTTP/1.1");
    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_target(target, 443)?;
        return Ok(LocalRequest::HttpConnect { host, port });
    }
    let absolute = target
        .strip_prefix("http://")
        .context("普通 HTTP 代理仅支持 http:// 绝对 URL")?;
    let (authority, path) = absolute
        .split_once('/')
        .map(|(authority, path)| (authority, format!("/{path}")))
        .unwrap_or((absolute, "/".into()));
    let (host, port) = split_target(authority, 80)?;
    let mut rewritten = format!("{method} {path} {version}\r\n").into_bytes();
    for line in text.lines().skip(1) {
        if line.is_empty() || line.to_ascii_lowercase().starts_with("proxy-connection:") {
            continue;
        }
        rewritten.extend_from_slice(line.as_bytes());
        rewritten.extend_from_slice(b"\r\n");
    }
    rewritten.extend_from_slice(b"Connection: close\r\n\r\n");
    Ok(LocalRequest::HttpPlain {
        host,
        port,
        initial: rewritten,
    })
}

fn split_target(value: &str, default_port: u16) -> Result<(String, u16)> {
    if let Ok(address) = value.parse::<SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            if !host.is_empty() && port != 0 {
                return Ok((host.trim_matches(['[', ']']).to_ascii_lowercase(), port));
            }
        }
    }
    if value.is_empty() {
        bail!("代理目标为空");
    }
    Ok((value.to_ascii_lowercase(), default_port))
}

async fn accept_local(stream: &mut TcpStream, request: &LocalRequest) -> Result<()> {
    match request {
        LocalRequest::Socks { .. } => socks_reply(stream, REP_OK).await,
        LocalRequest::SocksUdp { .. } => socks_reply(stream, REP_OK).await,
        LocalRequest::HttpConnect { .. } => {
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;
            Ok(())
        }
        LocalRequest::HttpPlain { .. } => Ok(()),
    }
}

async fn reject_local(stream: &mut TcpStream, request: &LocalRequest) -> Result<()> {
    match request {
        LocalRequest::Socks { .. } => socks_reply(stream, REP_FORBIDDEN).await,
        LocalRequest::SocksUdp { .. } => socks_reply(stream, REP_FORBIDDEN).await,
        _ => {
            stream
                .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
                .await?;
            Ok(())
        }
    }
}

async fn fail_local(stream: &mut TcpStream, request: &LocalRequest) -> Result<()> {
    match request {
        LocalRequest::Socks { .. } => socks_reply(stream, REP_HOST_UNREACHABLE).await,
        LocalRequest::SocksUdp { .. } => socks_reply(stream, REP_HOST_UNREACHABLE).await,
        _ => {
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await?;
            Ok(())
        }
    }
}

async fn serve_local_udp_association(
    state: ClientState,
    mut control: TcpStream,
    requested_port: u16,
) -> Result<()> {
    let bind = if control.local_addr()?.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    };
    let socket = UdpSocket::bind(bind).await?;
    socks_reply_address(&mut control, REP_OK, socket.local_addr()?).await?;
    let client_ip = control.peer_addr()?.ip();
    let mut buffer = vec![0u8; MAX_SOCKS_UDP_FRAME];
    let mut exit_sessions: HashMap<String, tokio_rustls::client::TlsStream<TcpStream>> =
        HashMap::new();
    let mut nearest_cache = None;
    loop {
        tokio::select! {
            control_result = control.read_u8() => {
                match control_result {
                    Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
                    Ok(_) | Err(_) => return Ok(()),
                }
            }
            datagram = socket.recv_from(&mut buffer) => {
                let (length, source) = datagram?;
                if source.ip() != client_ip || (requested_port != 0 && source.port() != requested_port) {
                    continue;
                }
                let frame = &buffer[..length];
                match route_local_udp(
                    &state,
                    frame,
                    &mut exit_sessions,
                    &mut nearest_cache,
                ).await {
                    Ok(response) => {
                        socket.send_to(&response, source).await?;
                    }
                    Err(error) => {
                        tracing::debug!(device = %state.device, "本地 UDP 数据报转发失败：{error:#}");
                    }
                }
            }
        }
    }
}

async fn route_local_udp(
    state: &ClientState,
    frame: &[u8],
    exit_sessions: &mut HashMap<String, tokio_rustls::client::TlsStream<TcpStream>>,
    nearest_cache: &mut Option<DeviceExit>,
) -> Result<Vec<u8>> {
    let packet = parse_socks_udp_packet(frame)?;
    let config = state.config.read().await.clone();
    let resolved = direct_candidates(&packet.host, packet.port).await.ok();
    let ip = resolved
        .as_ref()
        .and_then(|addresses| addresses.first())
        .map(SocketAddr::ip);
    match classify_config(&config, &packet.host, ip)? {
        Decision::Reject => bail!("UDP 目标被出口规则拒绝"),
        Decision::Direct => {
            let addresses = resolved.context("UDP 直连目标无法解析")?;
            let payload =
                udp_exchange(&addresses, &packet.payload, Duration::from_secs(15)).await?;
            encode_socks_udp_packet(&SocksUdpPacket { payload, ..packet })
        }
        Decision::Node(node_id) => {
            let exit = config
                .exits
                .iter()
                .find(|exit| exit.node_id == node_id)
                .cloned()
                .with_context(|| format!("指定出口节点 {node_id} 当前不可达"))?;
            exchange_exit_udp(state, &exit, frame, exit_sessions).await
        }
        Decision::Nearest => {
            if nearest_cache.as_ref().is_none_or(|cached| {
                !config
                    .exits
                    .iter()
                    .any(|exit| exit.node_id == cached.node_id)
            }) {
                *nearest_cache = Some(nearest_exit(&config.exits).await?);
            }
            let exit = nearest_cache.as_ref().context("当前没有可达出口节点")?;
            exchange_exit_udp(state, exit, frame, exit_sessions).await
        }
    }
}

async fn exchange_exit_udp(
    state: &ClientState,
    exit: &DeviceExit,
    frame: &[u8],
    sessions: &mut HashMap<String, tokio_rustls::client::TlsStream<TcpStream>>,
) -> Result<Vec<u8>> {
    let mut last_error = None;
    for _ in 0..2 {
        if !sessions.contains_key(&exit.node_id) {
            match connect_exit_udp_association(state, exit).await {
                Ok(stream) => {
                    sessions.insert(exit.node_id.clone(), stream);
                }
                Err(error) => {
                    last_error = Some(error);
                    continue;
                }
            }
        }
        let result = udp_tunnel_request(
            sessions
                .get_mut(&exit.node_id)
                .context("UDP 出口会话未建立")?,
            frame,
        )
        .await;
        match result {
            Ok(response) => return Ok(response),
            Err(error) => {
                last_error = Some(error);
                sessions.remove(&exit.node_id);
            }
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("UDP 出口连接失败")))
}

async fn udp_tunnel_request<S>(stream: &mut S, frame: &[u8]) -> Result<Vec<u8>>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if frame.is_empty() || frame.len() > MAX_SOCKS_UDP_FRAME {
        bail!("UDP 隧道请求帧长度无效");
    }
    tokio::time::timeout(Duration::from_secs(30), async {
        stream.write_u32(frame.len() as u32).await?;
        stream.write_all(frame).await?;
        stream.flush().await?;
        let status = stream.read_u8().await?;
        let length = stream.read_u32().await? as usize;
        if status != REP_OK {
            bail!("出口拒绝 UDP 数据报（SOCKS 状态 {status}）");
        }
        if length == 0 || length > MAX_SOCKS_UDP_FRAME {
            bail!("出口 UDP 响应帧长度无效");
        }
        let mut response = vec![0u8; length];
        stream.read_exact(&mut response).await?;
        Ok(response)
    })
    .await
    .context("UDP 出口响应超时")?
}

async fn nearest_exit(exits: &[DeviceExit]) -> Result<DeviceExit> {
    if exits.is_empty() {
        bail!("当前没有可达出口节点");
    }
    let probes = futures_util::future::join_all(exits.iter().cloned().map(|exit| async move {
        let started = Instant::now();
        let result = resolve_endpoint(&exit.endpoint)
            .await
            .and_then(|addresses| addresses.first().copied().context("出口端点没有解析结果"));
        let reachable = match result {
            Ok(address) => {
                tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(address))
                    .await
                    .is_ok_and(|result| result.is_ok())
            }
            Err(_) => false,
        };
        (exit, reachable.then(|| started.elapsed()))
    }))
    .await;
    probes
        .into_iter()
        .filter_map(|(exit, latency)| latency.map(|latency| (exit, latency)))
        .min_by_key(|(_, latency)| *latency)
        .map(|(exit, _)| exit)
        .context("所有出口节点均不可达")
}

async fn resolve_endpoint(endpoint: &str) -> Result<Vec<SocketAddr>> {
    if let Ok(address) = endpoint.parse::<SocketAddr>() {
        return Ok(vec![address]);
    }
    let (host, port) = endpoint
        .rsplit_once(':')
        .context("出口端点不是 hostname:port")?;
    let port: u16 = port.parse().context("出口端点端口无效")?;
    let mut addresses = tokio::net::lookup_host((host, port))
        .await?
        .collect::<Vec<_>>();
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        bail!("出口端点没有解析结果");
    }
    Ok(addresses)
}

fn endpoint_server_name(endpoint: &str) -> Result<ServerName<'static>> {
    let host = if let Ok(address) = endpoint.parse::<SocketAddr>() {
        address.ip().to_string()
    } else {
        endpoint
            .rsplit_once(':')
            .map(|(host, _)| host.trim_matches(['[', ']']).to_string())
            .context("出口端点缺少端口")?
    };
    if let Ok(ip) = host.parse::<IpAddr>() {
        Ok(ServerName::IpAddress(ip.into()))
    } else {
        Ok(ServerName::try_from(host).context("出口 TLS 主机名无效")?)
    }
}

async fn connect_exit(
    state: &ClientState,
    exit: &DeviceExit,
    host: &str,
    port: u16,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let addresses = resolve_endpoint(&exit.endpoint).await?;
    let tcp = connect_candidates(&addresses, Duration::from_secs(10)).await?;
    let connector = TlsConnector::from(state.tls.clone());
    let mut tls = connector
        .connect(endpoint_server_name(&exit.endpoint)?, tcp)
        .await
        .with_context(|| format!("连接 TLS 出口 {}", exit.label))?;
    client_socks_connect(&mut tls, &state.device, state.token.as_str(), host, port).await?;
    Ok(tls)
}

async fn connect_exit_udp_association(
    state: &ClientState,
    exit: &DeviceExit,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let addresses = resolve_endpoint(&exit.endpoint).await?;
    let tcp = connect_candidates(&addresses, Duration::from_secs(10)).await?;
    let connector = TlsConnector::from(state.tls.clone());
    let mut tls = connector
        .connect(endpoint_server_name(&exit.endpoint)?, tcp)
        .await
        .with_context(|| format!("连接 TLS UDP 出口 {}", exit.label))?;
    client_socks_command(
        &mut tls,
        &state.device,
        state.token.as_str(),
        CMD_UDP_ASSOCIATE,
        "0.0.0.0",
        0,
    )
    .await?;
    Ok(tls)
}

async fn client_socks_connect<S>(
    stream: &mut S,
    device: &str,
    token: &str,
    host: &str,
    port: u16,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    client_socks_command(stream, device, token, CMD_CONNECT, host, port).await
}

async fn client_socks_command<S>(
    stream: &mut S,
    device: &str,
    token: &str,
    command: u8,
    host: &str,
    port: u16,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !matches!(command, CMD_CONNECT | CMD_UDP_ASSOCIATE) {
        bail!("SOCKS 出口命令不受支持");
    }
    if device.len() > u8::MAX as usize
        || token.len() > u8::MAX as usize
        || host.len() > u8::MAX as usize
    {
        bail!("设备或目标名称过长");
    }
    let mut request = vec![SOCKS_VERSION, 1, AUTH_PASSWORD];
    request.extend_from_slice(&[1, device.len() as u8]);
    request.extend_from_slice(device.as_bytes());
    request.push(token.len() as u8);
    request.extend_from_slice(token.as_bytes());
    request.extend_from_slice(&[SOCKS_VERSION, command, 0, ATYP_DOMAIN, host.len() as u8]);
    request.extend_from_slice(host.as_bytes());
    request.extend_from_slice(&port.to_be_bytes());
    stream.write_all(&request).await?;
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method != [SOCKS_VERSION, AUTH_PASSWORD] {
        bail!("出口拒绝设备认证方法");
    }
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).await?;
    if auth != [1, 0] {
        bail!("出口拒绝设备令牌");
    }
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[0] != SOCKS_VERSION || reply[1] != REP_OK {
        bail!("出口拒绝目标连接（SOCKS 状态 {}）", reply[1]);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_node() -> (Arc<Node>, rf_core::identity::AnyKeypair) {
        let operator =
            rf_core::identity::AnyKeypair::Ed(rf_core::identity::Keypair::from_seed([61u8; 32]));
        let data_dir = std::env::temp_dir().join(format!(
            "rf-exit-proxy-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let config: crate::config::NodeConfig = toml::from_str(&format!(
            r#"
            data_dir = {data_dir:?}
            cluster_id = "exit-test"
            label = "exit-node"
            operator = "{operator}"
            cluster_secret = "abababababababababababababababababababababababababababababababab"
            [gossip]
            listen = "127.0.0.1:27381"
            advertise = "127.0.0.1:27381"
            [peer_api]
            listen = "127.0.0.1:27382"
            advertise = "127.0.0.1:27382"
            "#,
            data_dir = data_dir.display(),
            operator = operator.signer_id(),
        ))
        .unwrap();
        let node = Arc::new(
            Node::open(config, rf_core::identity::Keypair::from_seed([62u8; 32])).unwrap(),
        );
        (node, operator)
    }

    #[test]
    fn strict_egress_blocks_internal_metadata_and_reserved_ranges() {
        for address in [
            "127.0.0.1",
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "100.64.0.1",
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "64:ff9b::c0a8:101",
            "64:ff9b:1::c0a8:101",
            "100::1",
            "2001::1",
            "2002:c0a8:101::1",
            "3fff::1",
        ] {
            assert!(!public_egress_ip(address.parse().unwrap()), "{address}");
        }
        for address in ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"] {
            assert!(public_egress_ip(address.parse().unwrap()), "{address}");
        }
    }

    #[test]
    fn socks_udp_frames_preserve_all_address_types_and_reject_fragments() {
        for packet in [
            SocksUdpPacket {
                host: "dns.example".into(),
                port: 53,
                payload: vec![0, 1, 2, 255],
            },
            SocksUdpPacket {
                host: "1.1.1.1".into(),
                port: 53,
                payload: b"ipv4".to_vec(),
            },
            SocksUdpPacket {
                host: "2606:4700:4700::1111".into(),
                port: 53,
                payload: b"ipv6".to_vec(),
            },
        ] {
            let frame = encode_socks_udp_packet(&packet).unwrap();
            assert_eq!(parse_socks_udp_packet(&frame).unwrap(), packet);
        }
        let mut fragmented = encode_socks_udp_packet(&SocksUdpPacket {
            host: "dns.example".into(),
            port: 53,
            payload: vec![],
        })
        .unwrap();
        fragmented[2] = 1;
        assert!(parse_socks_udp_packet(&fragmented).is_err());
        assert!(parse_socks_udp_packet(&vec![0; MAX_SOCKS_UDP_FRAME + 1]).is_err());
    }

    #[tokio::test]
    async fn udp_exchange_uses_connected_source_and_preserves_binary_payload() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = echo.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut payload = [0u8; 128];
            let (length, peer) = echo.recv_from(&mut payload).await.unwrap();
            let mut response = b"echo:".to_vec();
            response.extend_from_slice(&payload[..length]);
            echo.send_to(&response, peer).await.unwrap();
        });
        let response = udp_exchange(&[address], &[0, 1, 255], Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(response, b"echo:\0\x01\xff");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn udp_tunnel_protocol_is_length_bounded_and_reusable() {
        let (mut client, mut server) = tokio::io::duplex(MAX_SOCKS_UDP_FRAME * 2);
        let server_task = tokio::spawn(async move {
            for suffix in [b"one".as_slice(), b"two".as_slice()] {
                let length = server.read_u32().await.unwrap() as usize;
                let mut request = vec![0u8; length];
                server.read_exact(&mut request).await.unwrap();
                let mut packet = parse_socks_udp_packet(&request).unwrap();
                packet.payload.extend_from_slice(suffix);
                let response = encode_socks_udp_packet(&packet).unwrap();
                server.write_u8(REP_OK).await.unwrap();
                server.write_u32(response.len() as u32).await.unwrap();
                server.write_all(&response).await.unwrap();
            }
        });
        let request = encode_socks_udp_packet(&SocksUdpPacket {
            host: "dns.example".into(),
            port: 53,
            payload: b"query-".to_vec(),
        })
        .unwrap();
        let first = udp_tunnel_request(&mut client, &request).await.unwrap();
        assert_eq!(
            parse_socks_udp_packet(&first).unwrap().payload,
            b"query-one"
        );
        let second = udp_tunnel_request(&mut client, &request).await.unwrap();
        assert_eq!(
            parse_socks_udp_packet(&second).unwrap().payload,
            b"query-two"
        );
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn local_socks_udp_associate_routes_direct_datagrams_end_to_end() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut payload = [0u8; 128];
            let (length, peer) = echo.recv_from(&mut payload).await.unwrap();
            echo.send_to(&payload[..length], peer).await.unwrap();
        });
        let config = DeviceConfig {
            schema: 1,
            cluster_id: "udp-test".into(),
            device: "phone".into(),
            label: "手机".into(),
            rules: vec![DeviceRule {
                name: "direct".into(),
                version: 1,
                digest: "00".repeat(32),
                spec: ExitRuleSpec {
                    schema: crate::exit::EXIT_RULE_SCHEMA,
                    description: "UDP 直连".into(),
                    enabled: true,
                    priority: 0,
                    format: crate::exit::RuleFormat::Surge,
                    config: "FINAL,DIRECT".into(),
                    providers: Default::default(),
                    policy_exits: Default::default(),
                },
            }],
            exits: vec![],
            refresh_after_seconds: 30,
        };
        let state = ClientState {
            control: "https://unused.test".into(),
            device: "phone".into(),
            token: Arc::new(Zeroizing::new("unused".into())),
            config: Arc::new(RwLock::new(config)),
            tls: Arc::new(
                rustls::ClientConfig::builder()
                    .with_root_certificates(rustls::RootCertStore::empty())
                    .with_no_client_auth(),
            ),
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_local(state, stream).await.unwrap();
        });

        let mut control = TcpStream::connect(proxy_address).await.unwrap();
        control
            .write_all(&[5, 1, 0, 5, CMD_UDP_ASSOCIATE, 0, ATYP_V4, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut method = [0u8; 2];
        control.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [SOCKS_VERSION, AUTH_NONE]);
        let mut reply = [0u8; 10];
        control.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[..4], [SOCKS_VERSION, REP_OK, 0, ATYP_V4]);
        let relay_address = SocketAddr::from((
            [reply[4], reply[5], reply[6], reply[7]],
            u16::from_be_bytes([reply[8], reply[9]]),
        ));

        let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = encode_socks_udp_packet(&SocksUdpPacket {
            host: echo_address.ip().to_string(),
            port: echo_address.port(),
            payload: vec![0, 1, 2, 255],
        })
        .unwrap();
        client_udp.send_to(&request, relay_address).await.unwrap();
        let mut response = vec![0u8; MAX_SOCKS_UDP_FRAME];
        let (length, source) =
            tokio::time::timeout(Duration::from_secs(2), client_udp.recv_from(&mut response))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(source, relay_address);
        response.truncate(length);
        assert_eq!(
            parse_socks_udp_packet(&response).unwrap().payload,
            vec![0, 1, 2, 255]
        );
        drop(control);
        echo_task.await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), proxy_task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn socks_client_handshake_is_pipelined_and_bounded() {
        let (mut client, mut server) = tokio::io::duplex(4_096);
        let server_task = tokio::spawn(async move {
            let mut bytes = vec![0u8; 3 + 2 + 6 + 1 + 47 + 5 + 11 + 2];
            server.read_exact(&mut bytes).await.unwrap();
            assert_eq!(&bytes[..3], &[5, 1, 2]);
            server.write_all(&[5, 2, 1, 0]).await.unwrap();
            server
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        client_socks_connect(
            &mut client,
            "phone1",
            "rfd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "example.com",
            443,
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn udp_association_authenticates_before_tunnel_frames() {
        let (mut client, mut server) = tokio::io::duplex(4_096);
        let server_task = tokio::spawn(async move {
            let mut bytes = vec![0u8; 3 + 2 + 6 + 1 + 47 + 5 + 7 + 2];
            server.read_exact(&mut bytes).await.unwrap();
            let command_offset = 3 + 2 + 6 + 1 + 47;
            assert_eq!(bytes[command_offset + 1], CMD_UDP_ASSOCIATE);
            assert_eq!(&bytes[bytes.len() - 2..], &[0, 0]);
            server.write_all(&[5, 2, 1, 0]).await.unwrap();
            server
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        client_socks_command(
            &mut client,
            "phone1",
            "rfd_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            CMD_UDP_ASSOCIATE,
            "0.0.0.0",
            0,
        )
        .await
        .unwrap();
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn tls_exit_authenticates_device_and_reuses_signed_rule_on_server() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (node, operator) = test_node();
        let spec = ExitRuleSpec {
            schema: crate::exit::EXIT_RULE_SCHEMA,
            description: "TLS 端到端".into(),
            enabled: true,
            priority: 0,
            format: crate::exit::RuleFormat::Surge,
            config: "DOMAIN,example.com,Exit\nFINAL,REJECT".into(),
            providers: Default::default(),
            policy_exits: std::collections::BTreeMap::from([(
                "Exit".into(),
                crate::exit::ExitTarget::Node {
                    node_id: node.id_hex(),
                },
            )]),
        };
        spec.validate().unwrap();
        let rule = crate::resource::prepare_after(
            crate::exit::EXIT_RULE_KIND,
            "default-route",
            serde_json::to_value(spec).unwrap(),
            false,
            None,
        )
        .unwrap();
        crate::resource::ingest(
            &node,
            &rf_core::envelope::Envelope::seal_any(&rule, &operator),
        )
        .unwrap();
        let (device, token) = crate::exit::mint_device(
            &node,
            "phone",
            "手机".into(),
            vec!["default-route".into()],
            None,
        )
        .unwrap();
        crate::resource::ingest(
            &node,
            &rf_core::envelope::Envelope::seal_any(&device, &operator),
        )
        .unwrap();

        let generated = rcgen::generate_simple_self_signed(vec!["exit.test".into()]).unwrap();
        let cert = generated.cert.der().clone();
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into());
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert).unwrap();
        let connector = TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let server_node = node.clone();
        let server = tokio::spawn(async move {
            let mut tls = acceptor.accept(server_io).await.unwrap();
            let (principal, request) = server_socks_handshake(&server_node, &mut tls)
                .await
                .unwrap();
            let EgressRequest::Connect { host, port } = request else {
                panic!("expected CONNECT request");
            };
            assert_eq!(principal.name, "phone");
            assert_eq!(host, "example.com");
            assert_eq!(port, 443);
            assert_eq!(
                device_decision(&server_node, &principal, &host, None).unwrap(),
                Decision::Node(server_node.id_hex())
            );
            socks_reply(&mut tls, REP_OK).await.unwrap();
        });
        let name = ServerName::try_from("exit.test").unwrap();
        let mut tls = connector.connect(name, client_io).await.unwrap();
        client_socks_connect(&mut tls, "phone", &token, "example.com", 443)
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[test]
    fn out_of_order_device_dependency_fails_closed_until_rule_arrives() {
        let (node, operator) = test_node();
        let (device, token) = crate::exit::mint_device_record(
            "laptop",
            "电脑".into(),
            vec!["not-synced-yet".into()],
            None,
        )
        .unwrap();
        // KV anti-entropy may deliver independently signed resource records in
        // either order. The record is valid, but it must not authenticate
        // before all explicitly bound rules are visible on this node.
        crate::resource::ingest(
            &node,
            &rf_core::envelope::Envelope::seal_any(&device, &operator),
        )
        .unwrap();
        assert!(crate::exit::resolve_device(&node, "laptop", &token).is_none());
        let view = crate::exit::device_views(&node).pop().unwrap();
        assert!(!view.rules_ready);
        assert!(!view.active);
    }
}
