const token = document.querySelector('meta[name="rf-console-token"]').content;
const consoleMode = document.querySelector('meta[name="rf-console-mode"]').content;
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

if (consoleMode === "public") document.body.classList.add("auth-required");

const state = {
  overview: null,
  session: null,
  view: "overview",
  busy: 0,
  kvSelected: null,
  authChallenge: null,
  authTimer: null,
  approvalTimer: null,
  approvalComplete: null,
  sources: [],
  builds: [],
  buildTimer: null,
  activeLog: null,
  activeWorker: null,
  workerDetail: null,
  projectTab: "overview",
};

const titles = {
  overview: ["集群控制", "概览"],
  workers: ["签名清单", "Worker"],
  "worker-new": ["Worker 项目", "新建项目"],
  "worker-detail": ["Worker 项目", "项目详情"],
  kv: ["分布式数据", "KV 存储"],
  d1: ["分布式 SQLite", "D1 数据库"],
};

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function shortId(value, length = 12) {
  const text = String(value || "—");
  return text.length > length ? `${text.slice(0, length)}…` : text;
}

function setBusy(active) {
  state.busy += active ? 1 : -1;
  state.busy = Math.max(0, state.busy);
  $("#loading").classList.toggle("active", state.busy > 0);
}

function showError(message = "") {
  const box = $("#global-error");
  box.textContent = message;
  box.classList.toggle("hidden", !message);
}

let toastTimer;
function toast(message, error = false) {
  const box = $("#toast");
  box.textContent = message;
  box.classList.toggle("error", error);
  box.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => box.classList.remove("show"), 3600);
}

async function api(path, options = {}) {
  setBusy(true);
  try {
    const headers = new Headers(options.headers || {});
    if (consoleMode === "local") headers.set("x-rf-console-token", token);
    if (consoleMode === "public" && state.session?.csrf && options.method && options.method !== "GET") {
      headers.set("x-rf-csrf", state.session.csrf);
    }
    if (options.body && !headers.has("content-type")) {
      headers.set("content-type", "application/json");
    }
    const response = await fetch(path, { ...options, headers });
    const type = response.headers.get("content-type") || "";
    const payload = type.includes("application/json")
      ? await response.json()
      : await response.text();
    if (!response.ok) {
      const error = new Error(payload?.error || payload || `请求失败（HTTP ${response.status}）`);
      error.status = response.status;
      throw error;
    }
    return payload;
  } finally {
    setBusy(false);
  }
}

function authorizationCommand(code, node) {
  return `RF_NODE=${node} RF_CLUSTER_SECRET='填入64位十六进制集群密钥' RF_OPERATOR_KEY=~/.rf/operator.key rf authorize ${code}`;
}

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const previous = button.textContent;
    button.textContent = "已复制";
    setTimeout(() => { button.textContent = previous; }, 1200);
  } catch {
    toast("复制失败，请手动选中并复制命令", true);
  }
}

async function beginAuthorization() {
  clearTimeout(state.authTimer);
  state.authChallenge = null;
  document.body.classList.add("auth-required");
  $("#auth-gate").classList.remove("hidden");
  $("#auth-retry").classList.add("hidden");
  $("#auth-dot").className = "dot pending";
  $("#auth-status").textContent = "正在创建签名请求";
  $("#auth-code").textContent = "正在生成…";
  try {
    const response = await fetch("/api/auth/challenge", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `创建授权请求失败（HTTP ${response.status}）`);
    state.authChallenge = data;
    const command = authorizationCommand(data.code, data.approve_node);
    $("#auth-code").textContent = data.code;
    $("#auth-command").textContent = command;
    $("#auth-status").textContent = "正在等待管理员签名";
    state.authTimer = setTimeout(pollAuthorization, 900);
  } catch (error) {
    $("#auth-dot").className = "dot offline";
    $("#auth-status").textContent = error.message;
    $("#auth-code").textContent = "生成失败";
    $("#auth-command").textContent = "请检查连接后重新生成授权请求";
    $("#auth-retry").classList.remove("hidden");
  }
}

async function pollAuthorization() {
  const challenge = state.authChallenge;
  if (!challenge) return;
  try {
    const response = await fetch(`/api/auth/challenge/${encodeURIComponent(challenge.id)}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `身份验证失败（HTTP ${response.status}）`);
    if (data.state === "completed") {
      $("#auth-dot").className = "dot online";
      $("#auth-status").textContent = "管理员身份已验证";
      document.body.classList.remove("auth-required");
      $("#auth-gate").classList.add("hidden");
      state.authChallenge = null;
      await boot();
      return;
    }
    state.authTimer = setTimeout(pollAuthorization, 900);
  } catch (error) {
    $("#auth-dot").className = "dot offline";
    $("#auth-status").textContent = error.message;
    $("#auth-retry").classList.remove("hidden");
  }
}

function switchView(view) {
  state.view = view;
  const navView = view.startsWith("worker-") ? "workers" : view;
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === navView));
  $$(".view").forEach((item) => item.classList.toggle("active", item.id === `view-${view}`));
  const title = titles[view] || titles.overview;
  $("#section-eyebrow").textContent = title[0];
  $("#section-title").textContent = title[1];
}

function renderOverview(data) {
  state.overview = data;
  const peers = Array.isArray(data.peers) ? data.peers : [];
  const workers = Array.isArray(data.workers) ? data.workers : [];
  const databases = Array.isArray(data.databases) ? data.databases : [];
  const allNodes = [
    {
      id: data.node,
      label: data.label || "本地节点",
      public: Boolean(data.public),
      api: data.console?.connected_to || "—",
      local: true,
    },
    ...peers,
  ];

  $("#metric-nodes").textContent = String(allNodes.length);
  $("#metric-public").textContent = `其中 ${allNodes.filter((node) => node.public).length} 个公网节点`;
  $("#metric-workers").textContent = String(workers.length);
  const routeCount = workers.reduce((total, worker) => total + (worker.hostnames?.length || 0), 0);
  $("#metric-routes").textContent = `${routeCount} 条主机名路由`;
  $("#metric-databases").textContent = String(databases.length);
  $("#metric-blobs").textContent = String(data.missing_blobs ?? 0);
  $("#cluster-version").textContent = `rf ${data.version || "—"}`;
  $("#node-label").textContent = data.label || "未命名节点";
  $("#node-id").textContent = data.node || "—";
  $("#node-api").textContent = data.console?.connected_to || "—";
  $("#operator-id").textContent = data.console?.operator || "尚未配置";
  $("#manifest-digest").textContent = data.manifest_digest || "节点尚未上报";
  $("#console-mode").textContent = data.console?.read_only ? "只读" : "管理员模式";
  $("#worker-nav-count").textContent = String(workers.length);
  $("#worker-count").textContent = `运行中 ${workers.length} 个`;

  $("#node-list").classList.remove("empty-state");
  $("#node-list").innerHTML = allNodes
    .map((node) => `
      <div class="node-row">
        <span class="dot online" title="在线"></span>
        <div><div class="node-name">${escapeHtml(node.label || "未命名")}${node.local ? " · 当前节点" : ""}</div><div class="node-short">${escapeHtml(shortId(node.id))}</div></div>
        <div class="node-address">${escapeHtml(node.api || node.ip4 || "地址不可用")}</div>
        <span class="badge">${node.public ? "公网" : "内网"}</span>
      </div>`)
    .join("");

  const strip = $("#overview-workers");
  strip.classList.toggle("empty-state", workers.length === 0);
  strip.innerHTML = workers.length
    ? workers.slice(0, 6).map((worker) => `
      <button class="worker-card" type="button" data-open-worker="${escapeHtml(worker.name)}">
        <strong>${escapeHtml(worker.name)} <span class="badge">v${escapeHtml(worker.version)}</span></strong>
        <p>${escapeHtml(worker.hostnames?.join(", ") || "未配置主机名")}</p>
      </button>`).join("")
    : "暂无运行中的 Worker。";

  renderWorkers(workers);
  renderDatabases(databases);
  renderNamespaces(Array.isArray(data.kv_namespaces) ? data.kv_namespaces : []);
  $("#connection-dot").className = "dot online";
  $("#connection-text").textContent = `已连接 · ${data.label || "节点"}`;
  showError();
}

function renderWorkers(workers) {
  const table = $("#workers-table");
  const mutationDisabled = state.session?.read_only
    ? ' disabled title="请先加载管理员密钥，再修改 Worker"'
    : "";
  table.innerHTML = workers.length
    ? workers.map((worker) => {
      const content = worker.modules
        ? `${worker.modules} 个模块 · ${worker.assets || 0} 个静态资源`
        : `${worker.assets || 0} 个静态资源`;
      const distribution = worker.distribution || { ready: 0, total: 1, nodes: [] };
      const complete = distribution.ready === distribution.total;
      const nodeStates = (distribution.nodes || []).map((node) => {
        const status = node.status || {};
        return `${node.label || shortId(node.node)}：${deploymentStateLabel(status.state)} v${status.version || "—"}`;
      }).join("\n");
      const source = state.sources.find((item) => item.worker === worker.name);
      const subtitle = source
        ? source.repository.replace(/\.git$/, "").replace(/^https:\/\/github\.com\//, "")
        : worker.hostnames?.[0] || "手动部署";
      return `<tr>
        <td><button class="project-name" data-action="open-worker" data-worker="${escapeHtml(worker.name)}"><span class="project-icon">W</span><span><strong>${escapeHtml(worker.name)}</strong><small>${escapeHtml(subtitle)}</small></span></button></td>
        <td class="mono">v${escapeHtml(worker.version)}</td>
        <td>${escapeHtml(content)}</td>
        <td><small>${escapeHtml(worker.hostnames?.join(", ") || "—")}</small></td>
        <td><span class="${complete ? "state-ok" : "state-wait"}" title="${escapeHtml(nodeStates)}">${escapeHtml(distribution.ready)}/${escapeHtml(distribution.total)} 个节点</span><small>${complete ? "已完成全量分发" : "正在收敛"}</small></td>
        <td><div class="table-actions"><button class="mini-button" data-action="open-worker" data-worker="${escapeHtml(worker.name)}">打开</button></div></td>
      </tr>`;
    }).join("")
    : '<tr><td colspan="6" class="empty-state">暂无 Worker。</td></tr>';
}

function deploymentStateLabel(stateName) {
  return {
    running: "运行中",
    starting: "正在启动",
    failed: "失败",
    waiting_blobs: "正在获取内容块",
    standby: "待命",
    runtime_unavailable: "运行时不可用",
  }[stateName] || stateName || "未知";
}

function buildStateLabel(stateName) {
  return {
    queued: "已排队",
    cloning: "正在克隆",
    building: "正在构建",
    packaging: "正在打包",
    awaiting_approval: "等待签名",
    deployed: "已部署",
    failed: "失败",
  }[stateName] || stateName || "未知";
}

function buildTriggerLabel(trigger) {
  if (trigger === "manual") return "手动触发";
  if (String(trigger || "").startsWith("github:")) return "GitHub 推送";
  return trigger || "未知来源";
}

function renderSources(data) {
  state.sources = data.sources || [];
  const capabilities = data.capabilities || {};
  const cap = $("#build-capabilities");
  const gitReady = Boolean(capabilities.git);
  const sandboxReady = Boolean(capabilities.sandbox);
  cap.innerHTML = `
    <div><span class="dot ${gitReady ? "online" : "offline"}"></span><p><strong>${gitReady ? "构建节点已就绪" : "Git 不可用"}</strong><small>Git ${gitReady ? "可用" : "缺失"}</small></p></div>
    <div><span class="dot ${sandboxReady ? "online" : "pending"}"></span><p><strong>${sandboxReady ? "构建沙箱已启用" : "仅支持零配置构建"}</strong><small>bwrap ${sandboxReady ? "可用" : "未配置"}</small></p></div>
    <div><span class="dot ${capabilities.github_token_configured ? "online" : "pending"}"></span><p><strong>${capabilities.github_token_configured ? "可访问私有仓库" : "仅公开仓库"}</strong><small>节点令牌${capabilities.github_token_configured ? "已配置" : "未配置"}</small></p></div>`;
  if (state.overview?.workers) renderWorkers(state.overview.workers);
}

function buildRowsHtml(jobs, approveNode) {
  return jobs.length ? jobs.map((job) => {
    const terminal = job.state === "deployed" || job.state === "failed";
    const short = job.commit ? job.commit.slice(0, 12) : "等待中";
    const approval = job.approval && job.state === "awaiting_approval"
      ? `<button class="primary" data-build-action="approve" data-build="${escapeHtml(job.id)}" data-node="${escapeHtml(job.approve_node || approveNode || "")}">签署发布</button>` : "";
    return `<article class="build-row ${job.state === "failed" ? "failed" : ""}">
      <span class="pipeline-state ${terminal ? job.state : "active"}"></span>
      <div><strong>${escapeHtml(job.worker)}</strong><small>${escapeHtml(buildTriggerLabel(job.trigger))} · ${escapeHtml(job.branch)} · <code>${escapeHtml(short)}</code></small></div>
      <div class="build-stage"><span class="badge ${job.state === "deployed" ? "active" : ""}">${escapeHtml(buildStateLabel(job.state))}</span><small>${job.version ? `发布 v${escapeHtml(job.version)}` : "产物尚未就绪"}</small></div>
      <div class="table-actions">${approval}<button class="mini-button" data-build-action="log" data-build="${escapeHtml(job.id)}">查看日志</button></div>
    </article>`;
  }).join("") : '<div class="empty-state">暂无构建记录。连接仓库后即可开始首次构建。</div>';
}

function renderBuilds(jobs, approveNode) {
  state.builds = jobs || [];
  if (state.activeWorker) {
    $("#detail-builds").innerHTML = buildRowsHtml(
      state.builds.filter((job) => job.worker === state.activeWorker),
      approveNode,
    );
  }
}

function formatBytes(bytes) {
  const value = Number(bytes || 0);
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / (1024 * 1024)).toFixed(1)} MiB`;
}

function workerUrl(hostname, tlsEnabled = location.protocol === "https:") {
  if (!hostname) return "";
  return `${tlsEnabled ? "https:" : "http:"}//${hostname}`;
}

function mapToLines(values) {
  return Object.entries(values || {}).map(([key, value]) => `${key}=${value}`).join("\n");
}

function linesToMap(value, label) {
  const result = {};
  for (const [index, raw] of String(value || "").split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line) continue;
    const split = line.indexOf("=");
    if (split <= 0) throw new Error(`${label}第 ${index + 1} 行必须采用 KEY=value 格式`);
    const key = line.slice(0, split).trim();
    if (Object.hasOwn(result, key)) throw new Error(`${label}包含重复名称：${key}`);
    result[key] = line.slice(split + 1);
  }
  return result;
}

function switchProjectTab(tab) {
  state.projectTab = tab;
  $$('[data-project-tab]').forEach((button) => button.classList.toggle("active", button.dataset.projectTab === tab));
  $$(".project-tab").forEach((panel) => panel.classList.toggle("active", panel.id === `project-tab-${tab}`));
  if (tab === "logs") loadDetailLogs();
  if (tab === "deployments") loadDetailHistory();
}

function certificateStatusLabel(status) {
  return {
    active: "证书有效",
    installed: "证书已安装",
    renewing: "即将续期",
    provisioning: "正在签发",
    acme_unavailable: "ACME 未就绪",
    expired: "证书已过期",
    missing: "缺少受信任证书",
    https_disabled: "HTTPS 未启用",
    unknown: "状态不可用",
  }[status] || status || "状态不可用";
}

function certificateStateClass(status) {
  if (status === "active" || status === "installed") return "ok";
  if (status === "renewing" || status === "provisioning") return "wait";
  return "error";
}

function renderProjectDomains(worker, tls = {}) {
  const hostnames = worker.hostnames || [];
  const certificates = new Map((tls.certificates || []).map((item) => [item.hostname, item]));
  const trusted = (tls.certificates || []).filter((item) => ["active", "installed", "renewing"].includes(item.status)).length;
  const automaticConfigured = Boolean(tls.acme_enabled && tls.include_worker_hostnames);
  const automatic = Boolean(automaticConfigured && tls.acme_ready);
  $("#project-domain-count").textContent = `${hostnames.length} 个域名`;
  $("#domain-tls-summary").innerHTML = `
    <article class="domain-metric"><span>路由状态</span><strong>${hostnames.length ? "已发布" : "待配置"}</strong><small>${hostnames.length} 个域名写入当前清单</small></article>
    <article class="domain-metric"><span>HTTPS 入口</span><strong>${tls.enabled ? "已启用" : "未启用"}</strong><small>${tls.enabled ? "节点正在监听 HTTPS" : "请先在节点配置 ingress.https"}</small></article>
    <article class="domain-metric"><span>受信任证书</span><strong>${trusted}/${hostnames.length}</strong><small>${automatic ? "新增域名可由 ACME 自动签发" : automaticConfigured ? "ACME 缺少可用的 DNS 区域或令牌" : tls.acme_enabled ? "ACME 仅管理节点配置中的域名" : "当前节点未配置 ACME"}</small></article>`;

  const list = $("#project-domain-list");
  list.classList.toggle("empty-state", hostnames.length === 0);
  list.innerHTML = hostnames.length ? hostnames.map((hostname) => {
    const cert = certificates.get(hostname) || { status: "unknown", source: "unknown", coverage: "unknown" };
    const url = workerUrl(hostname, Boolean(tls.enabled));
    const source = cert.source === "acme" ? "ACME 自动管理" : cert.source === "manual" ? "手动证书" : "无证书";
    const coverage = cert.coverage === "wildcard"
      ? `通配符 ${cert.covered_by || ""}`
      : cert.coverage === "exact" ? "精确域名" : "未覆盖";
    const expiry = cert.expires_ms
      ? `有效至 ${new Date(cert.expires_ms).toLocaleDateString("zh-CN")}${cert.days_remaining != null ? ` · 剩余 ${cert.days_remaining} 天` : ""}`
      : cert.status === "installed" ? "有效期由手动证书决定" : "尚无有效期信息";
    return `<div class="domain-row">
      <span class="domain-icon">↗</span>
      <div class="domain-primary"><a href="${escapeHtml(url)}" target="_blank" rel="noreferrer">${escapeHtml(hostname)}</a><small>${escapeHtml(url)}</small></div>
      <div class="domain-route"><span class="status-chip ok">路由已发布</span><small>Worker v${escapeHtml(worker.version)}</small></div>
      <div class="domain-certificate"><span class="status-chip ${certificateStateClass(cert.status)}">${escapeHtml(certificateStatusLabel(cert.status))}</span><small>${escapeHtml(source)} · ${escapeHtml(coverage)}</small><small>${escapeHtml(expiry)}</small></div>
      <button class="mini-button danger" type="button" data-remove-domain="${escapeHtml(hostname)}">移除</button>
    </div>`;
  }).join("") : "尚未绑定域名。添加域名后，所有节点会从同一份签名清单建立路由。";

  const dnsInstruction = tls.dns_target
    ? `将域名的 CNAME 指向 ${tls.dns_target}；RandallFlare 的 DNS 轮换会维护可用边缘节点。`
    : "将域名的 A/AAAA 或 CNAME 记录指向承担入口流量的 RandallFlare 公网节点。";
  const certificateInstruction = automatic
    ? `域名位于 ${tls.zone || "已配置区域"} 内时，集群会抢占签发任务，并通过 DNS-01 自动申请和续期。`
    : automaticConfigured
      ? "Worker 域名自动签发已开启，但当前节点缺少 DNS 区域或 API 令牌；补全节点侧 ACME 配置后才会开始签发。"
    : tls.acme_enabled
      ? "如需自动签发新绑定的域名，请在节点的 [acme] 中启用 include_worker_hostnames，或预先配置覆盖它的通配符证书。"
      : "请在节点的 [acme] 中配置 DNS-01，或把 .crt/.key 证书放入 data_dir/certs；证书会热加载。";
  $("#project-domain-guidance").innerHTML = `
    <div><span>1</span><p><strong>发布路由</strong><small>这里的添加或移除操作会生成新的签名 Worker 清单。</small></p></div>
    <div><span>2</span><p><strong>配置 DNS</strong><small>${escapeHtml(dnsInstruction)}</small></p></div>
    <div><span>3</span><p><strong>启用 HTTPS</strong><small>${escapeHtml(certificateInstruction)}</small></p></div>`;
}

function renderWorkerDetail(data) {
  const worker = data.worker;
  const summary = (state.overview?.workers || []).find((item) => item.name === worker.name) || {};
  const source = data.source || state.sources.find((item) => item.worker === worker.name) || null;
  const distribution = summary.distribution || { ready: 0, total: 1, nodes: [] };
  const modules = worker.modules || [];
  const assets = worker.assets || [];
  const totalBytes = [...modules, ...assets].reduce((total, item) => total + Number(item.size || 0), 0);
  const openUrl = workerUrl(worker.hostnames?.[0], Boolean(data.tls?.enabled));

  $("#project-title").textContent = worker.name;
  $("#project-subtitle").textContent = source
    ? `${source.repository.replace(/\.git$/, "")} · ${source.branch}`
    : "由签名部署包管理 · 尚未连接 GitHub";
  $("#section-title").textContent = worker.name;
  $("#detail-status").textContent = distribution.ready === distribution.total ? "生产环境就绪" : "正在分发";
  $("#detail-status").classList.toggle("active", distribution.ready === distribution.total);
  $("#project-open").classList.toggle("hidden", !openUrl);
  if (openUrl) $("#project-open").href = openUrl;
  $("#detail-deployment").innerHTML = `
    <div class="deployment-version"><span class="deployment-check">✓</span><div><strong>v${escapeHtml(worker.version)}</strong><p>${source ? "由 GitHub 构建流水线发布" : "由 Worker 包直接发布"}</p></div></div>
    <dl class="detail-list compact"><div><dt>清单摘要</dt><dd class="mono">${escapeHtml(worker.digest)}</dd></div><div><dt>入口模块</dt><dd class="mono">${escapeHtml(worker.main || "静态资源项目")}</dd></div><div><dt>兼容日期</dt><dd>${escapeHtml(worker.compatibility_date)}</dd></div></dl>`;
  $("#detail-summary").innerHTML = `
    <div><dt>当前版本</dt><dd>v${escapeHtml(worker.version)}</dd></div>
    <div><dt>域名</dt><dd>${escapeHtml(worker.hostnames?.length || 0)} 个</dd></div>
    <div><dt>环境变量</dt><dd>${escapeHtml(Object.keys(worker.env || {}).length)} 项</dd></div>
    <div><dt>KV 绑定</dt><dd>${escapeHtml(Object.keys(worker.kv_bindings || {}).length)} 项</dd></div>
    <div><dt>定时任务</dt><dd>${escapeHtml(worker.crons?.length || 0)} 条</dd></div>`;
  $("#detail-distribution-count").textContent = `${distribution.ready}/${distribution.total} 个节点`;
  $("#detail-distribution").innerHTML = (distribution.nodes || []).map((node) => {
    const status = node.status || {};
    return `<div class="node-row"><span class="dot ${status.state === "running" ? "online" : "pending"}"></span><div><div class="node-name">${escapeHtml(node.label || shortId(node.node))}</div><div class="node-short">${escapeHtml(shortId(node.node, 18))}</div></div><div class="node-address">${escapeHtml(deploymentStateLabel(status.state))}</div><span class="badge">v${escapeHtml(status.version || "—")}</span></div>`;
  }).join("") || '<div class="empty-state">尚无节点分发状态。</div>';
  $("#detail-content").innerHTML = `
    <div class="content-metrics"><div><strong>${modules.length}</strong><span>模块</span></div><div><strong>${assets.length}</strong><span>静态资源</span></div><div><strong>${formatBytes(totalBytes)}</strong><span>总大小</span></div></div>
    <div class="content-files"><strong>主要内容</strong>${[...modules, ...assets].slice(0, 6).map((file) => `<span><code>${escapeHtml(file.path)}</code><small>${formatBytes(file.size)}</small></span>`).join("") || '<span class="muted">清单中没有文件</span>'}</div>`;
  renderProjectDomains(worker, data.tls || {});
  $("#project-env").value = mapToLines(worker.env);
  $("#project-kv-bindings").value = mapToLines(worker.kv_bindings);
  $("#project-crons").value = (worker.crons || []).join("\n");
  $("#project-compatibility-date").value = worker.compatibility_date;
  $("#project-source-repository").value = source?.repository?.replace(/\.git$/, "") || "";
  $("#project-source-branch").value = source?.branch || "main";
  $("#project-source-root").value = source?.root || ".";
  $("#project-source-command").value = source?.build_command || "";
  $("#project-source-output").value = source?.output_dir || ".";
  $("#project-source-private").checked = Boolean(source?.use_github_token);
  $("#project-source-webhook").checked = source ? Boolean(source.webhook) : true;
  $("#project-source-panel .settings-copy .muted").textContent = source
    ? "编辑仓库、分支与构建命令。源码配置也由管理员签名并在集群内复制。"
    : "该项目尚未连接 GitHub；填写配置即可接入构建与推送部署。";
  $("#project-source-form button[type=submit]").textContent = source ? "保存 Git 配置" : "连接 GitHub 仓库";
  $("#project-source-disconnect").classList.toggle("hidden", !source);
  $("#project-source-status").innerHTML = source ? `
    <div class="source-connection"><span class="dot online"></span><p><strong>已连接</strong><small>代码源 v${escapeHtml(source.version)} · ${source.webhook ? "推送自动构建已启用" : "仅手动构建"}</small></p></div>
    ${source.webhook ? `<div class="webhook-grid"><span>回调地址</span><code>${escapeHtml(`${location.origin}${source.webhook_path}`)}</code><span>密钥</span><code>${escapeHtml(source.webhook_secret || "不可用")}</code><span>事件</span><code>仅推送事件</code></div>` : ""}` : '<div class="source-connection"><span class="dot pending"></span><p><strong>尚未连接</strong><small>填写右侧表单即可启用 GitHub 构建。</small></p></div>';
  $("#project-identifiers").innerHTML = `
    <div><dt>Worker 名称</dt><dd class="mono">${escapeHtml(worker.name)}</dd></div>
    <div><dt>当前版本</dt><dd class="mono">v${escapeHtml(worker.version)}</dd></div>
    <div><dt>清单摘要</dt><dd class="mono">${escapeHtml(worker.digest)}</dd></div>
    <div><dt>入口模块</dt><dd class="mono">${escapeHtml(worker.main || "静态资源项目")}</dd></div>`;
  $("#detail-builds").innerHTML = buildRowsHtml(state.builds.filter((job) => job.worker === worker.name));
}

async function openWorkerDetail(name, tab = "overview") {
  state.activeWorker = name;
  state.workerDetail = null;
  switchView("worker-detail");
  switchProjectTab(tab);
  $("#project-title").textContent = name;
  $("#project-subtitle").textContent = "正在加载项目详情…";
  try {
    const data = await api(`/api/workers/${encodeURIComponent(name)}`);
    if (state.activeWorker !== name) return;
    state.workerDetail = data;
    renderWorkerDetail(data);
    await Promise.all([loadDetailHistory(), tab === "logs" ? loadDetailLogs() : Promise.resolve()]);
  } catch (error) {
    toast(error.message, true);
    switchView("workers");
  }
}

async function loadDetailHistory() {
  const name = state.activeWorker;
  if (!name) return;
  try {
    const data = await api(`/api/workers/${encodeURIComponent(name)}/log`);
    if (state.activeWorker !== name) return;
    $("#detail-history").innerHTML = `<p class="muted"><span class="state-ok">✓ 哈希链验证通过</span> · ${data.entries.length} 个版本</p>${data.entries.slice().reverse().map((entry, index) => `<div class="history-entry"><div class="version">v${escapeHtml(entry.version)}</div><div>${escapeHtml(entry.hostnames?.join(", ") || "未配置域名")}<code>${escapeHtml(entry.digest)}</code></div>${!entry.deleted && index > 0 ? `<button class="mini-button" data-rollback-worker="${escapeHtml(name)}" data-rollback-version="${escapeHtml(entry.version)}">回滚</button>` : ""}</div>`).join("")}`;
  } catch (error) {
    $("#detail-history").innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
  }
}

async function loadDetailLogs() {
  const name = state.activeWorker;
  if (!name) return;
  $("#detail-logs").textContent = "正在读取运行日志…";
  try {
    const data = await api(`/api/workers/${encodeURIComponent(name)}/runtime-log?limit=500`);
    if (state.activeWorker !== name) return;
    const streams = { system: "系统", stdout: "标准输出", stderr: "标准错误" };
    $("#detail-log-meta").textContent = `节点 ${shortId(data.node, 20)} · 最近 ${data.lines?.length || 0} 条`;
    $("#detail-logs").textContent = (data.lines || []).map((line) => `${new Date(line.at_ms).toLocaleString("zh-CN")} [v${line.version}] [${streams[line.stream] || line.stream}] ${line.message}`).join("\n") || "当前节点尚未记录运行输出。";
  } catch (error) {
    $("#detail-logs").textContent = error.message;
  }
}

async function updateWorkerSettings(payload, summary) {
  const name = state.activeWorker;
  if (!name) return;
  try {
    const result = await api(`/api/workers/${encodeURIComponent(name)}`, { method: "PATCH", body: JSON.stringify(payload) });
    if (result.pending_approval) {
      showApproval(result, summary);
    } else {
      toast(`${name} v${result.version} 已发布`);
      await loadOverview({ quiet: true });
      await openWorkerDetail(name, state.projectTab);
    }
  } catch (error) {
    toast(error.message, true);
  }
}

async function saveProjectDomains(event) {
  event.preventDefault();
  const hostname = $("#project-domain-input").value.trim().replace(/^https?:\/\//, "").split("/")[0].replace(/\.$/, "").toLowerCase();
  const current = state.workerDetail?.worker?.hostnames || [];
  if (current.includes(hostname)) {
    toast(`${hostname} 已绑定到当前 Worker`, true);
    return;
  }
  const hostnames = [...current, hostname];
  await updateWorkerSettings({ hostnames }, `为 ${state.activeWorker} 添加域名 ${hostname}。`);
  $("#project-domain-input").value = "";
}

async function removeProjectDomain(hostname) {
  if (!window.confirm(`要从 ${state.activeWorker} 移除域名“${hostname}”吗？`)) return;
  const hostnames = (state.workerDetail?.worker?.hostnames || []).filter((item) => item !== hostname);
  await updateWorkerSettings({ hostnames }, `从 ${state.activeWorker} 移除域名 ${hostname}。`);
}

async function saveProjectBindings(event) {
  event.preventDefault();
  try {
    const payload = {
      env: linesToMap($("#project-env").value, "环境变量"),
      kv_bindings: linesToMap($("#project-kv-bindings").value, "KV 绑定"),
    };
    await updateWorkerSettings(payload, `更新 ${state.activeWorker} 的变量与绑定。`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function saveProjectTriggers(event) {
  event.preventDefault();
  const crons = $("#project-crons").value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
  await updateWorkerSettings({ crons }, `更新 ${state.activeWorker} 的定时触发器。`);
}

async function saveProjectSettings(event) {
  event.preventDefault();
  await updateWorkerSettings(
    { compatibility_date: $("#project-compatibility-date").value },
    `更新 ${state.activeWorker} 的兼容日期。`,
  );
}

async function saveProjectSource(event) {
  event.preventDefault();
  const payload = {
    worker: state.activeWorker,
    repository: $("#project-source-repository").value.trim(),
    branch: $("#project-source-branch").value.trim(),
    root: $("#project-source-root").value.trim(),
    build_command: $("#project-source-command").value,
    output_dir: $("#project-source-output").value.trim(),
    use_github_token: $("#project-source-private").checked,
    webhook: $("#project-source-webhook").checked,
  };
  try {
    const result = await api("/api/sources", { method: "POST", body: JSON.stringify(payload) });
    showApproval(result, `保存 ${payload.worker} 的 GitHub 代码源配置。`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function loadWorkerOps({ quiet = true } = {}) {
  if (consoleMode !== "public" || !state.session) return;
  try {
    const [sources, builds] = await Promise.all([api("/api/sources"), api("/api/builds")]);
    renderSources(sources);
    renderBuilds(builds.jobs, builds.approve_node);
  } catch (error) {
    if (!quiet) toast(error.message, true);
  }
}

async function connectSource(event) {
  event.preventDefault();
  const payload = {
    worker: $("#source-worker").value.trim(),
    repository: $("#source-repository").value.trim(),
    branch: $("#source-branch").value.trim(),
    root: $("#source-root").value.trim(),
    build_command: $("#source-command").value,
    output_dir: $("#source-output").value.trim(),
    use_github_token: $("#source-private").checked,
    webhook: $("#source-webhook").checked,
  };
  try {
    const result = await api("/api/sources", { method: "POST", body: JSON.stringify(payload) });
    showApproval(result, `将 ${payload.worker} 连接到 GitHub。`, async () => {
      switchView("workers");
      await triggerBuild(payload.worker);
    });
  } catch (error) {
    toast(error.message, true);
  }
}

function editSource(worker) {
  const source = state.sources.find((item) => item.worker === worker);
  if (!source) return;
  $("#source-worker").value = source.worker;
  $("#source-repository").value = source.repository.replace(/\.git$/, "");
  $("#source-branch").value = source.branch;
  $("#source-root").value = source.root;
  $("#source-command").value = source.build_command;
  $("#source-output").value = source.output_dir;
  $("#source-private").checked = source.use_github_token;
  $("#source-webhook").checked = source.webhook;
  $("#source-form").scrollIntoView({ behavior: "smooth", block: "center" });
}

async function disconnectSource(worker) {
  if (!window.confirm(`要断开“${worker}”与 GitHub 的连接吗？已部署的版本将继续运行。`)) return;
  try {
    const result = await api(`/api/sources/${encodeURIComponent(worker)}`, { method: "DELETE" });
    showApproval(result, `断开 ${worker} 与此仓库的连接。`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function triggerBuild(worker) {
  try {
    const result = await api(`/api/workers/${encodeURIComponent(worker)}/build`, { method: "POST", body: "{}" });
    toast(`${worker} 的构建任务已进入队列`);
    await loadWorkerOps();
    if (state.activeWorker === worker) switchProjectTab("deployments");
    openBuildLog(result.job.id);
  } catch (error) {
    toast(error.message, true);
  }
}

async function openBuildLog(id) {
  clearTimeout(state.buildTimer);
  state.activeLog = { type: "build", id };
  $("#log-eyebrow").textContent = "实时构建日志";
  $("#log-title").textContent = "构建记录";
  $("#log-dialog").showModal();
  await refreshBuildLog(id);
}

async function refreshBuildLog(id) {
  if (state.activeLog?.type !== "build" || state.activeLog.id !== id) return;
  try {
    const data = await api(`/api/builds/${encodeURIComponent(id)}`);
    const job = data.job;
    $("#log-title").textContent = `${job.worker} · ${buildStateLabel(job.state)}`;
    $("#log-meta").textContent = `${job.repository} · ${job.branch}${job.commit ? ` · ${job.commit}` : ""}`;
    $("#log-content").textContent = (job.log || []).join("\n") || "正在等待构建输出…";
    $("#log-content").scrollTop = $("#log-content").scrollHeight;
    if (job.state === "awaiting_approval" || job.state === "deployed" || job.state === "failed") {
      await loadWorkerOps();
    }
    if (job.state !== "deployed" && job.state !== "failed") {
      state.buildTimer = setTimeout(() => refreshBuildLog(id), 1000);
    }
  } catch (error) {
    $("#log-content").textContent += `\n${error.message}`;
  }
}

function approveBuild(id, approveNode) {
  const job = state.builds.find((item) => item.id === id);
  if (!job?.approval) return;
  showApproval({
    name: job.worker,
    version: job.version,
    approval: job.approval,
    approve_node: approveNode,
  }, `部署为 ${job.worker} 构建的不可变产物。`);
}

async function openRuntimeLog(worker) {
  clearTimeout(state.buildTimer);
  state.activeLog = { type: "runtime", worker };
  $("#log-eyebrow").textContent = "本节点运行日志";
  $("#log-title").textContent = worker;
  $("#log-dialog").showModal();
  try {
    const data = await api(`/api/workers/${encodeURIComponent(worker)}/runtime-log?limit=500`);
    $("#log-meta").textContent = `节点 ${shortId(data.node, 20)} · 有界内存日志`;
    const streams = { system: "系统", stdout: "标准输出", stderr: "标准错误" };
    $("#log-content").textContent = (data.lines || []).map((line) => `${new Date(line.at_ms).toISOString()} [v${line.version}] [${streams[line.stream] || line.stream}] ${line.message}`).join("\n") || "当前节点尚未记录运行输出。";
    $("#log-content").scrollTop = $("#log-content").scrollHeight;
  } catch (error) {
    $("#log-content").textContent = error.message;
  }
}

function renderDatabases(databases) {
  const list = $("#database-list");
  list.classList.toggle("empty-state", databases.length === 0);
  list.innerHTML = databases.length
    ? databases.map((name) => `<button class="database-button" type="button" data-database="${escapeHtml(name)}"><span>${escapeHtml(name)}</span><span>查询 →</span></button>`).join("")
    : "暂无数据库。";
}

function renderNamespaces(namespaces) {
  $("#kv-namespaces").innerHTML = namespaces
    .map((namespace) => `<option value="${escapeHtml(namespace)}"></option>`)
    .join("");
}

async function loadOverview({ quiet = false } = {}) {
  try {
    const data = await api("/api/overview");
    renderOverview(data);
    if (!quiet) toast("集群状态已刷新");
  } catch (error) {
    if (consoleMode === "public" && error.status === 401) {
      state.session = null;
      showError("");
      if (!state.authChallenge) await beginAuthorization();
      return;
    }
    $("#connection-dot").className = "dot offline";
    $("#connection-text").textContent = "连接已断开";
    showError(error.message);
    if (!quiet) toast(error.message, true);
  }
}

async function loadHistory(name) {
  try {
    const data = await api(`/api/workers/${encodeURIComponent(name)}/log`);
    $("#history-title").textContent = `${name} 的版本历史`;
    $("#history-content").innerHTML = `
      <p class="muted"><span class="state-ok">✓ 哈希链验证通过</span> · 签名者 ${escapeHtml(shortId(data.signer, 24))}</p>
      ${data.entries.slice().reverse().map((entry, index) => `<div class="history-entry"><div class="version">v${escapeHtml(entry.version)}${entry.deleted ? " · 已删除" : ""}</div><div>${escapeHtml(entry.hostnames?.join(", ") || "未配置路由")}<code>${escapeHtml(entry.digest)}</code></div>${!entry.deleted && index > 0 ? `<button class="mini-button" data-rollback-worker="${escapeHtml(name)}" data-rollback-version="${escapeHtml(entry.version)}">回滚</button>` : ""}</div>`).join("") || '<p class="empty-state">暂无历史记录。</p>'}`;
    $("#history-dialog").showModal();
  } catch (error) {
    toast(error.message, true);
  }
}

async function rollbackWorker(worker, version) {
  if (!window.confirm(`要将 ${worker} v${version} 的内容重新部署为一个新的签名版本吗？`)) return;
  try {
    const result = await api(`/api/workers/${encodeURIComponent(worker)}/rollback/${encodeURIComponent(version)}`, { method: "POST", body: "{}" });
    $("#history-dialog").close();
    showApproval(result, `将 ${worker} 回滚到 v${version} 的内容。`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteWorker(name) {
  if (!window.confirm(`要删除 Worker“${name}”吗？系统将写入墓碑记录，既有历史仍可验证。`)) return;
  try {
    const result = await api(`/api/workers/${encodeURIComponent(name)}`, { method: "DELETE" });
    if (result.pending_approval) {
      showApproval(result, `管理员批准后，${name} 将被标记为已删除。`);
    } else {
      toast(`${name} 已在 v${result.version} 写入删除标记`);
      if (state.activeWorker === name) {
        state.activeWorker = null;
        state.workerDetail = null;
        switchView("workers");
      }
      await loadOverview({ quiet: true });
    }
  } catch (error) {
    toast(error.message, true);
  }
}

function bytesToBase64(bytes) {
  let binary = "";
  const chunk = 0x8000;
  for (let offset = 0; offset < bytes.length; offset += chunk) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + chunk));
  }
  return btoa(binary);
}

function updateDeployFileStatus() {
  const selected = Array.from($("#deploy-files").files || []);
  if (!selected.length) {
    $("#deploy-file-status").textContent = "尚未选择目录";
    return;
  }
  const firstPath = selected[0].webkitRelativePath || selected[0].name;
  const directory = firstPath.includes("/") ? firstPath.split("/")[0] : "所选目录";
  $("#deploy-file-status").textContent = `${directory} · ${selected.length} 个文件`;
}

async function browserBundleFiles() {
  const selected = Array.from($("#deploy-files").files || []);
  if (!selected.length) throw new Error("请选择 Worker 包目录");
  const rawPaths = selected.map((file) => file.webkitRelativePath || file.name);
  const firstRoot = rawPaths[0].split("/")[0];
  const stripRoot = rawPaths.every((path) => path.startsWith(`${firstRoot}/`));
  const files = [];
  let total = 0;
  for (let index = 0; index < selected.length; index += 1) {
    const file = selected[index];
    const bytes = new Uint8Array(await file.arrayBuffer());
    total += bytes.length;
    if (total > 64 * 1024 * 1024) throw new Error("Worker 包不能超过 64 MiB");
    const raw = rawPaths[index];
    const path = stripRoot ? raw.slice(firstRoot.length + 1) : raw;
    files.push({ path, data_base64: bytesToBase64(bytes) });
  }
  return files;
}

function showApproval(result, fallbackSummary, onComplete = null) {
  clearTimeout(state.approvalTimer);
  state.approvalComplete = onComplete;
  const approval = result.approval;
  const command = authorizationCommand(approval.code, result.approve_node);
  $("#approval-title").textContent = result.name
    ? `${result.name} v${result.version}`
    : "批准集群变更";
  $("#approval-summary").textContent = approval.summary || fallbackSummary;
  $("#approval-code").textContent = approval.code;
  $("#approval-command").textContent = command;
  $("#approval-dot").className = "dot pending";
  $("#approval-status").textContent = "正在等待管理员签名";
  $("#approval-dialog").showModal();
  state.approvalTimer = setTimeout(() => pollApproval(approval.id), 900);
}

async function pollApproval(id) {
  try {
    const result = await api(`/api/approvals/${encodeURIComponent(id)}`);
    if (result.state === "completed") {
      $("#approval-dot").className = "dot online";
      $("#approval-status").textContent = "签名已验证，变更已提交至集群";
      toast(result.summary || "集群变更已提交");
      await loadOverview({ quiet: true });
      await loadWorkerOps();
      if (state.activeWorker) await openWorkerDetail(state.activeWorker, state.projectTab);
      const onComplete = state.approvalComplete;
      state.approvalComplete = null;
      if (onComplete) {
        if ($("#approval-dialog").open) $("#approval-dialog").close();
        await onComplete(result);
      }
      return;
    }
    if (result.state === "failed") {
      throw new Error(result.error || "集群变更失败");
    }
    state.approvalTimer = setTimeout(() => pollApproval(id), 900);
  } catch (error) {
    $("#approval-dot").className = "dot offline";
    $("#approval-status").textContent = error.message;
    toast(error.message, true);
  }
}

async function loadKeys() {
  const namespace = $("#kv-namespace").value.trim();
  const prefix = $("#kv-prefix").value;
  if (!namespace) return;
  try {
    const query = new URLSearchParams({ namespace, prefix });
    const data = await api(`/api/kv?${query}`);
    $("#kv-count").textContent = `${data.keys.length} 个键`;
    const list = $("#kv-keys");
    list.classList.toggle("empty-state", data.keys.length === 0);
    list.innerHTML = data.keys.length
      ? data.keys.map((key) => `<button class="key-button" type="button" data-key="${escapeHtml(key)}"><span>${escapeHtml(key)}</span><span>编辑 →</span></button>`).join("")
      : "没有符合此前缀的键。";
  } catch (error) {
    toast(error.message, true);
  }
}

async function openKey(key) {
  const namespace = $("#kv-namespace").value.trim();
  try {
    const query = new URLSearchParams({ namespace, key });
    const data = await api(`/api/kv/value?${query}`);
    state.kvSelected = key;
    $("#kv-key").value = key;
    $("#kv-value").value = data.text ?? `[二进制值；Base64 编码]\n${data.base64}`;
    $("#kv-editor-title").textContent = key;
    $("#kv-delete").classList.remove("hidden");
  } catch (error) {
    toast(error.message, true);
  }
}

function clearKey() {
  state.kvSelected = null;
  $("#kv-key").value = "";
  $("#kv-value").value = "";
  $("#kv-editor-title").textContent = "新建键";
  $("#kv-delete").classList.add("hidden");
  $("#kv-key").focus();
}

async function saveKey(event) {
  event.preventDefault();
  const payload = {
    namespace: $("#kv-namespace").value.trim(),
    key: $("#kv-key").value,
    value: $("#kv-value").value,
  };
  try {
    await api("/api/kv/value", { method: "PUT", body: JSON.stringify(payload) });
    state.kvSelected = payload.key;
    $("#kv-delete").classList.remove("hidden");
    toast(`已保存 ${payload.namespace}/${payload.key}`);
    await loadKeys();
  } catch (error) {
    toast(error.message, true);
  }
}

async function removeKey() {
  const namespace = $("#kv-namespace").value.trim();
  const key = $("#kv-key").value;
  if (!key || !window.confirm(`要删除 ${namespace}/${key} 吗？`)) return;
  try {
    const query = new URLSearchParams({ namespace, key });
    await api(`/api/kv/value?${query}`, { method: "DELETE" });
    toast(`已删除 ${namespace}/${key}`);
    clearKey();
    await loadKeys();
  } catch (error) {
    toast(error.message, true);
  }
}

async function deployWorker(event) {
  event.preventDefault();
  try {
    const payload = consoleMode === "public"
      ? { files: await browserBundleFiles() }
      : { path: $("#deploy-path").value.trim() };
    const result = await api("/api/workers/deploy", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    if (result.pending_approval) {
      showApproval(result, `${result.name} v${result.version} 已准备就绪，等待签名。`, async () => {
        await openWorkerDetail(result.name);
      });
    } else {
      toast(`已部署 ${result.name} v${result.version}`);
      await loadOverview({ quiet: true });
    }
  } catch (error) {
    toast(error.message, true);
  }
}

async function createDatabase(event) {
  event.preventDefault();
  const name = $("#d1-create-name").value.trim();
  try {
    await api("/api/d1/create", { method: "POST", body: JSON.stringify({ name }) });
    $("#d1-name").value = name;
    $("#d1-create-name").value = "";
    toast(`已创建 D1 数据库 ${name}`);
    await loadOverview({ quiet: true });
  } catch (error) {
    toast(error.message, true);
  }
}

async function executeSql(event) {
  event.preventDefault();
  let params;
  try {
    params = JSON.parse($("#d1-params").value || "[]");
  } catch {
    toast("D1 参数必须是有效的 JSON", true);
    return;
  }
  const started = performance.now();
  try {
    const result = await api("/api/d1/exec", {
      method: "POST",
      body: JSON.stringify({
        name: $("#d1-name").value.trim(),
        sql: $("#d1-sql").value,
        params,
      }),
    });
    $("#d1-result").textContent = JSON.stringify(result, null, 2);
    $("#d1-result-meta").textContent = `${Math.round(performance.now() - started)} ms`;
    toast("SQL 执行成功");
  } catch (error) {
    $("#d1-result").textContent = error.message;
    $("#d1-result-meta").textContent = "执行失败";
    toast(error.message, true);
  }
}

async function boot() {
  try {
    state.session = await api("/api/session");
    document.body.classList.remove("auth-required");
    $("#auth-gate").classList.add("hidden");
    $("#logout").classList.toggle("hidden", consoleMode !== "public");
    $("#deploy-local-fields").classList.toggle("hidden", consoleMode === "public");
    $("#deploy-public-fields").classList.toggle("hidden", consoleMode !== "public");
    $("#deploy-path").required = consoleMode === "local";
    $("#github-import").classList.toggle("hidden", consoleMode !== "public");
    $("#import-divider").classList.toggle("hidden", consoleMode !== "public");
    $("#import-sidebar").classList.toggle("hidden", consoleMode !== "public");
    $("#deploy-mode").textContent = state.session.read_only
      ? "尚未加载管理员密钥，所有写操作均已禁用。"
      : consoleMode === "public"
        ? `已验证管理员 ${shortId(state.session.operator, 22)}。Worker 清单仍须通过 CLI 一次性批准。`
        : `当前签名身份：${shortId(state.session.operator, 22)}。`;
    $("#transport-warning").classList.toggle(
      "hidden",
      consoleMode !== "public" || state.session.secure_transport,
    );
    $("#security-copy").innerHTML = consoleMode === "public"
      ? "此节点不保存<br>任何私钥。"
      : "密钥仅保留在本地<br>控制台进程中。";
    $$("#deploy-form button, #source-form button, #kv-editor-form button, #d1-create-form button, #d1-exec-form button, #project-domain-add-form button, #project-bindings-form button, #project-triggers-form button, #project-settings-form button, #project-source-form button, #project-redeploy, #project-delete")
      .forEach((button) => { button.disabled = state.session.read_only; });
    await loadOverview({ quiet: true });
    await loadWorkerOps();
    await loadKeys();
  } catch (error) {
    if (consoleMode === "public" && error.status === 401) {
      state.session = null;
      if (!state.authChallenge) await beginAuthorization();
      return;
    }
    showError(error.message);
    toast(error.message, true);
  }
}

$$(".nav-item").forEach((button) => button.addEventListener("click", () => switchView(button.dataset.view)));
$$('[data-go]').forEach((button) => button.addEventListener("click", () => switchView(button.dataset.go)));
$("#overview-workers").addEventListener("click", (event) => {
  const button = event.target.closest("[data-open-worker]");
  if (button) openWorkerDetail(button.dataset.openWorker);
});
$("#new-project").addEventListener("click", () => {
  state.activeWorker = null;
  state.workerDetail = null;
  switchView("worker-new");
  window.scrollTo({ top: 0, behavior: "smooth" });
  setTimeout(() => $("#source-worker").focus(), 300);
});
$("#new-project-back").addEventListener("click", () => switchView("workers"));
$("#project-back").addEventListener("click", () => {
  state.activeWorker = null;
  state.workerDetail = null;
  switchView("workers");
});
$$("[data-project-tab]").forEach((button) => button.addEventListener("click", () => switchProjectTab(button.dataset.projectTab)));
$("#project-redeploy").addEventListener("click", () => {
  if (state.sources.some((source) => source.worker === state.activeWorker)) {
    triggerBuild(state.activeWorker);
  } else {
    switchProjectTab("source");
    $("#project-source-repository").focus();
    toast("请先连接 GitHub 仓库，再触发自动构建", true);
  }
});
$("#project-domain-add-form").addEventListener("submit", saveProjectDomains);
$("#project-bindings-form").addEventListener("submit", saveProjectBindings);
$("#project-triggers-form").addEventListener("submit", saveProjectTriggers);
$("#project-settings-form").addEventListener("submit", saveProjectSettings);
$("#project-source-form").addEventListener("submit", saveProjectSource);
$("#project-source-disconnect").addEventListener("click", () => state.activeWorker && disconnectSource(state.activeWorker));
$("#project-delete").addEventListener("click", () => state.activeWorker && deleteWorker(state.activeWorker));
$("#detail-refresh-logs").addEventListener("click", loadDetailLogs);
$("#refresh").addEventListener("click", () => loadOverview());
$("#deploy-form").addEventListener("submit", deployWorker);
$("#deploy-file-picker").addEventListener("click", () => $("#deploy-files").click());
$("#deploy-files").addEventListener("change", updateDeployFileStatus);
$("#source-form").addEventListener("submit", connectSource);
$("#kv-search-form").addEventListener("submit", (event) => { event.preventDefault(); loadKeys(); });
$("#kv-editor-form").addEventListener("submit", saveKey);
$("#kv-new").addEventListener("click", clearKey);
$("#kv-delete").addEventListener("click", removeKey);
$("#d1-create-form").addEventListener("submit", createDatabase);
$("#d1-exec-form").addEventListener("submit", executeSql);
$("#history-close").addEventListener("click", () => $("#history-dialog").close());
$("#log-close").addEventListener("click", () => {
  clearTimeout(state.buildTimer);
  state.activeLog = null;
  $("#log-dialog").close();
});
$("#approval-close").addEventListener("click", () => $("#approval-dialog").close());
$("#auth-retry").addEventListener("click", beginAuthorization);
$("#auth-copy").addEventListener("click", () => copyText($("#auth-command").textContent, $("#auth-copy")));
$("#approval-copy").addEventListener("click", () => copyText($("#approval-command").textContent, $("#approval-copy")));
$("#logout").addEventListener("click", async () => {
  try {
    await api("/api/auth/logout", { method: "POST", body: "{}" });
  } catch (error) {
    toast(error.message, true);
  }
  state.session = null;
  await beginAuthorization();
});
$("#workers-table").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-action]");
  if (!button) return;
  if (button.dataset.action === "open-worker") openWorkerDetail(button.dataset.worker);
  if (button.dataset.action === "history") loadHistory(button.dataset.worker);
  if (button.dataset.action === "runtime") openRuntimeLog(button.dataset.worker);
  if (button.dataset.action === "delete-worker") deleteWorker(button.dataset.worker);
});
$("#project-domain-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-remove-domain]");
  if (button) removeProjectDomain(button.dataset.removeDomain);
});
$("#detail-builds").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-build-action]");
  if (!button) return;
  if (button.dataset.buildAction === "log") openBuildLog(button.dataset.build);
  if (button.dataset.buildAction === "approve") approveBuild(button.dataset.build, button.dataset.node);
});
$("#detail-history").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-rollback-worker]");
  if (button) rollbackWorker(button.dataset.rollbackWorker, button.dataset.rollbackVersion);
});
$("#history-content").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-rollback-worker]");
  if (button) rollbackWorker(button.dataset.rollbackWorker, button.dataset.rollbackVersion);
});
$("#kv-keys").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-key]");
  if (button) openKey(button.dataset.key);
});
$("#database-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-database]");
  if (!button) return;
  $("#d1-name").value = button.dataset.database;
  $("#d1-sql").focus();
});

setInterval(() => {
  if (state.session) {
    loadOverview({ quiet: true });
    loadWorkerOps();
  }
}, 10_000);
boot();
