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
  r2Buckets: [],
  r2Active: null,
  r2Cursor: null,
  r2Objects: [],
  queues: [],
  queueActive: null,
  queueDeadLetters: [],
  analyticsDatasets: [],
  analyticsActive: null,
  analyticsEvents: [],
  analyticsGroups: [],
  pipelines: [],
  pipelineActive: null,
  pipelineBatches: [],
  workflows: [],
  workflowActive: null,
  workflowInstances: [],
  workflowInstanceActive: null,
};

const titles = {
  overview: ["集群控制", "概览"],
  workers: ["签名清单", "Worker"],
  "worker-new": ["Worker 项目", "新建项目"],
  "worker-detail": ["Worker 项目", "项目详情"],
  kv: ["分布式数据", "KV 存储"],
  r2: ["对象存储", "R2 bucket"],
  d1: ["分布式 SQLite", "D1 数据库"],
  queues: ["事件驱动", "队列"],
  analytics: ["可观测数据", "Analytics Engine"],
  pipelines: ["数据传输", "Pipeline"],
  workflows: ["耐久执行", "Workflow"],
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

function updateDefaultDomainPreview() {
  const preview = $("#source-default-domain");
  const domain = state.overview?.default_worker_domain;
  const worker = $("#source-worker").value.trim().toLowerCase();
  if (!domain) {
    preview.textContent = "当前节点尚未启用 Worker 默认域名";
  } else if (/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(worker)) {
    preview.textContent = `默认域名：https://${worker}.${domain}`;
  } else {
    preview.textContent = `填写名称后自动获得 <Worker名称>.${domain}`;
  }
}

function renderOverview(data) {
  state.overview = data;
  updateR2DefaultDomainPreview();
  const peers = Array.isArray(data.peers) ? data.peers : [];
  const workers = Array.isArray(data.workers) ? data.workers : [];
  const databases = Array.isArray(data.databases) ? data.databases : [];
  const buckets = Array.isArray(data.r2_buckets) ? data.r2_buckets : [];
  const queues = Array.isArray(data.queues) ? data.queues : [];
  const analyticsDatasets = Array.isArray(data.analytics_datasets) ? data.analytics_datasets : [];
  const pipelines = Array.isArray(data.pipelines) ? data.pipelines : [];
  const workflows = Array.isArray(data.workflows) ? data.workflows : [];
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
  $("#metric-r2").textContent = String(buckets.length);
  $("#metric-queues").textContent = String(queues.length);
  $("#queue-nav-count").textContent = String(queues.length);
  $("#metric-analytics").textContent = String(analyticsDatasets.length);
  $("#analytics-nav-count").textContent = String(analyticsDatasets.length);
  $("#metric-pipelines").textContent = String(pipelines.length);
  $("#pipeline-nav-count").textContent = String(pipelines.length);
  $("#metric-workflows").textContent = String(workflows.length);
  $("#workflow-nav-count").textContent = String(workflows.length);
  $("#metric-r2-backend").textContent = data.storage?.rclone ? "本地副本与 rclone 已就绪" : "集群本地多数派副本";
  $("#r2-nav-count").textContent = String(buckets.length);
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
  updateDefaultDomainPreview();

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
  const defaultHostname = worker.default_hostname || null;
  const certificates = new Map((tls.certificates || []).map((item) => [item.hostname, item]));
  const trusted = (tls.certificates || []).filter((item) => ["active", "installed", "renewing"].includes(item.status)).length;
  const automaticConfigured = Boolean(tls.acme_enabled && tls.include_worker_hostnames);
  const automatic = Boolean(automaticConfigured && tls.acme_ready);
  $("#project-domain-count").textContent = `${hostnames.length} 个域名`;
  $("#domain-tls-summary").innerHTML = `
    <article class="domain-metric"><span>路由状态</span><strong>${hostnames.length ? "已发布" : "待配置"}</strong><small>${hostnames.length} 个生效域名${defaultHostname ? " · 含系统默认域名" : ""}</small></article>
    <article class="domain-metric"><span>HTTPS 入口</span><strong>${tls.enabled ? "已启用" : "未启用"}</strong><small>${tls.enabled ? "节点正在监听 HTTPS" : "请先在节点配置 ingress.https"}</small></article>
    <article class="domain-metric"><span>受信任证书</span><strong>${trusted}/${hostnames.length}</strong><small>${automatic ? "新增域名可由 ACME 自动签发" : automaticConfigured ? "ACME 缺少可用的 DNS 区域或令牌" : tls.acme_enabled ? "ACME 仅管理节点配置中的域名" : "当前节点未配置 ACME"}</small></article>`;

  const list = $("#project-domain-list");
  list.classList.toggle("empty-state", hostnames.length === 0);
  list.innerHTML = hostnames.length ? hostnames.map((hostname) => {
    const isDefault = hostname === defaultHostname;
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
      <div class="domain-primary"><a href="${escapeHtml(url)}" target="_blank" rel="noreferrer">${escapeHtml(hostname)}</a><small>${isDefault ? "系统分配 · " : "自定义域名 · "}${escapeHtml(url)}</small></div>
      <div class="domain-route"><span class="status-chip ok">${isDefault ? "默认域名" : "路由已发布"}</span><small>Worker v${escapeHtml(worker.version)}</small></div>
      <div class="domain-certificate"><span class="status-chip ${certificateStateClass(cert.status)}">${escapeHtml(certificateStatusLabel(cert.status))}</span><small>${escapeHtml(source)} · ${escapeHtml(coverage)}</small><small>${escapeHtml(expiry)}</small></div>
      ${isDefault ? '<span class="badge active">始终可用</span>' : `<button class="mini-button danger" type="button" data-remove-domain="${escapeHtml(hostname)}">移除</button>`}
    </div>`;
  }).join("") : "尚未绑定域名。添加域名后，所有节点会从同一份签名清单建立路由。";

  const dnsInstruction = defaultHostname
    ? `默认域名 ${defaultHostname} 已由通配符 DNS 接入；仅添加自定义域名时需要配置 DNS。`
    : tls.dns_target
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
    <div><span>1</span><p><strong>默认域名</strong><small>${defaultHostname ? `每个节点都会独立推导 ${escapeHtml(defaultHostname)}，无需写入清单或申请分配。` : "当前节点尚未配置默认 Worker 域名。"}</small></p></div>
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
    <div><dt>R2 绑定</dt><dd>${escapeHtml(Object.keys(worker.r2_bindings || {}).length)} 项</dd></div>
    <div><dt>D1 绑定</dt><dd>${escapeHtml(Object.keys(worker.d1_bindings || {}).length)} 项</dd></div>
    <div><dt>Queue 绑定</dt><dd>${escapeHtml(Object.keys(worker.queue_bindings || {}).length)} 项</dd></div>
    <div><dt>Analytics 绑定</dt><dd>${escapeHtml(Object.keys(worker.analytics_bindings || {}).length)} 项</dd></div>
    <div><dt>Pipeline 绑定</dt><dd>${escapeHtml(Object.keys(worker.pipeline_bindings || {}).length)} 项</dd></div>
    <div><dt>Workflow 绑定</dt><dd>${escapeHtml(Object.keys(worker.workflow_bindings || {}).length)} 项</dd></div>
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
  $("#project-r2-bindings").value = mapToLines(worker.r2_bindings);
  $("#project-d1-bindings").value = mapToLines(worker.d1_bindings);
  $("#project-queue-bindings").value = mapToLines(worker.queue_bindings);
  $("#project-analytics-bindings").value = mapToLines(worker.analytics_bindings);
  $("#project-pipeline-bindings").value = mapToLines(worker.pipeline_bindings);
  $("#project-workflow-bindings").value = mapToLines(worker.workflow_bindings);
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
  const worker = state.workerDetail?.worker || {};
  const effective = worker.hostnames || [];
  const current = worker.custom_hostnames || effective.filter((item) => item !== worker.default_hostname);
  if (effective.includes(hostname)) {
    toast(`${hostname} 已绑定到当前 Worker`, true);
    return;
  }
  const hostnames = [...current, hostname];
  await updateWorkerSettings({ hostnames }, `为 ${state.activeWorker} 添加域名 ${hostname}。`);
  $("#project-domain-input").value = "";
}

async function removeProjectDomain(hostname) {
  const worker = state.workerDetail?.worker || {};
  if (hostname === worker.default_hostname) {
    toast("默认域名由节点自动分配，不能移除", true);
    return;
  }
  if (!window.confirm(`要从 ${state.activeWorker} 移除域名“${hostname}”吗？`)) return;
  const hostnames = (worker.custom_hostnames || worker.hostnames || []).filter((item) => item !== hostname && item !== worker.default_hostname);
  await updateWorkerSettings({ hostnames }, `从 ${state.activeWorker} 移除域名 ${hostname}。`);
}

async function saveProjectBindings(event) {
  event.preventDefault();
  try {
    const payload = {
      env: linesToMap($("#project-env").value, "环境变量"),
      kv_bindings: linesToMap($("#project-kv-bindings").value, "KV 绑定"),
      r2_bindings: linesToMap($("#project-r2-bindings").value, "R2 绑定"),
      d1_bindings: linesToMap($("#project-d1-bindings").value, "D1 绑定"),
      queue_bindings: linesToMap($("#project-queue-bindings").value, "Queue 绑定"),
      analytics_bindings: linesToMap($("#project-analytics-bindings").value, "Analytics 绑定"),
      pipeline_bindings: linesToMap($("#project-pipeline-bindings").value, "Pipeline 绑定"),
      workflow_bindings: linesToMap($("#project-workflow-bindings").value, "Workflow 绑定"),
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

function renderR2Buckets() {
  const list = $("#r2-bucket-list");
  $("#r2-bucket-count").textContent = `${state.r2Buckets.length} 个`;
  $("#r2-nav-count").textContent = String(state.r2Buckets.length);
  list.classList.toggle("empty-state", state.r2Buckets.length === 0);
  list.innerHTML = state.r2Buckets.length
    ? state.r2Buckets.map((bucket) => {
      const storage = bucket.spec?.storage || {};
      const backend = storage.type === "rclone"
        ? `rclone · ${storage.remote}`
        : "集群本地副本";
      const access = bucket.spec?.public_access ? "公开" : "私有";
      return `<button class="database-button r2-bucket-button${state.r2Active === bucket.name ? " active" : ""}" type="button" data-r2-bucket="${escapeHtml(bucket.name)}"><span><strong>${escapeHtml(bucket.name)}</strong><small>${escapeHtml(backend)} · ${access} · v${escapeHtml(bucket.version)}</small></span><span>打开 →</span></button>`;
    }).join("")
    : "暂无 R2 bucket。";
}

async function loadR2({ quiet = false } = {}) {
  try {
    const data = await api("/api/r2/buckets");
    state.r2Buckets = data.buckets || [];
    const rcloneReady = Boolean(data.capabilities?.rclone);
    $("#r2-capability").textContent = rcloneReady ? "本地副本 + rclone" : "集群本地副本";
    $("#r2-storage-backend").querySelector('option[value="rclone"]').disabled = !rcloneReady;
    if (!state.r2Buckets.some((bucket) => bucket.name === state.r2Active)) {
      state.r2Active = null;
      state.r2Objects = [];
      state.r2Cursor = null;
      $("#r2-active-bucket").textContent = "请选择 bucket";
      $("#r2-bucket-summary").textContent = "选择左侧 bucket 后即可管理对象。";
      $("#r2-object-tools").classList.add("hidden");
      $("#r2-delete-bucket").classList.add("hidden");
    }
    renderR2Buckets();
    if (!quiet) toast("R2 bucket 已刷新");
  } catch (error) {
    if (!quiet) toast(error.message, true);
  }
}

function numberOrNull(selector) {
  const value = $(selector).value.trim();
  return value ? Number(value) : null;
}

function fillR2BucketForm(bucket) {
  const spec = bucket?.spec || {};
  const storage = spec.storage || { type: "local" };
  $("#r2-bucket-name").value = bucket?.name || "";
  $("#r2-bucket-description").value = spec.description || "";
  $("#r2-storage-backend").value = storage.type || "local";
  $("#r2-rclone-remote").value = storage.remote || "";
  $("#r2-rclone-prefix").value = storage.prefix || "";
  $("#r2-max-bytes").value = spec.max_bytes ?? "";
  $("#r2-max-objects").value = spec.max_objects ?? "";
  $("#r2-expire-days").value = spec.expire_objects_after_days ?? "";
  $("#r2-cors-origins").value = (spec.cors_origins || []).join("\n");
  $("#r2-hostnames").value = (spec.hostnames || []).join("\n");
  $("#r2-public-access").checked = Boolean(spec.public_access);
  updateR2DefaultDomainPreview();
  toggleR2StorageFields();
}

async function saveR2Bucket(event) {
  event.preventDefault();
  const backend = $("#r2-storage-backend").value;
  const payload = {
    name: $("#r2-bucket-name").value.trim(),
    description: $("#r2-bucket-description").value.trim(),
    public_access: $("#r2-public-access").checked,
    storage_backend: backend,
    rclone_remote: backend === "rclone" ? $("#r2-rclone-remote").value.trim() : "",
    rclone_prefix: backend === "rclone" ? $("#r2-rclone-prefix").value.trim() : "",
    max_bytes: numberOrNull("#r2-max-bytes"),
    max_objects: numberOrNull("#r2-max-objects"),
    expire_objects_after_days: numberOrNull("#r2-expire-days"),
    cors_origins: $("#r2-cors-origins").value.split("\n").map((value) => value.trim()).filter(Boolean),
    hostnames: $("#r2-hostnames").value.split("\n").map((value) => value.trim().toLowerCase()).filter(Boolean),
  };
  try {
    const result = await api("/api/r2/buckets", { method: "POST", body: JSON.stringify(payload) });
    const complete = async () => {
      await loadOverview({ quiet: true });
      await loadR2({ quiet: true });
      await selectR2Bucket(payload.name);
    };
    if (result.pending_approval) {
      showApproval(result, `批准后，R2 bucket ${payload.name} 的签名配置将传播到集群。`, complete);
    } else {
      toast(`R2 bucket ${payload.name} 已保存`);
      await complete();
    }
  } catch (error) {
    toast(error.message, true);
  }
}

function updateR2DefaultDomainPreview() {
  const bucket = $("#r2-bucket-name").value.trim().toLowerCase();
  const domain = state.overview?.default_worker_domain;
  const preview = $("#r2-default-domain");
  if (!domain) {
    preview.textContent = "当前节点尚未启用默认公开域名";
  } else if (/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(bucket)) {
    preview.textContent = `默认公开域名：https://r2-${bucket}.${domain}/<对象键>`;
  } else {
    preview.textContent = `填写名称后自动获得 r2-<bucket>.${domain}`;
  }
}

function toggleR2StorageFields() {
  const rclone = $("#r2-storage-backend").value === "rclone";
  $("#r2-rclone-fields").classList.toggle("hidden", !rclone);
  $("#r2-rclone-remote").required = rclone;
}

async function selectR2Bucket(name) {
  const bucket = state.r2Buckets.find((item) => item.name === name);
  if (!bucket) return;
  state.r2Active = name;
  state.r2Objects = [];
  state.r2Cursor = null;
  fillR2BucketForm(bucket);
  const storage = bucket.spec?.storage || { type: "local" };
  $("#r2-active-bucket").textContent = name;
  const storageSummary = storage.type === "rclone"
    ? `rclone remote ${storage.remote}:${storage.prefix || "（根目录）"} · 配置 v${bucket.version}`
    : `集群本地多数派副本 · 配置 v${bucket.version}`;
  const publicHosts = [
    ...(state.overview?.default_worker_domain ? [`r2-${name}.${state.overview.default_worker_domain}`] : []),
    ...(bucket.spec?.hostnames || []),
  ];
  $("#r2-bucket-summary").textContent = bucket.spec?.public_access && publicHosts.length
    ? `${storageSummary} · 公开地址 https://${publicHosts[0]}/<对象键>`
    : storageSummary;
  $("#r2-object-tools").classList.remove("hidden");
  $("#r2-delete-bucket").classList.remove("hidden");
  renderR2Buckets();
  await loadR2Objects();
}

function renderR2Objects() {
  const table = $("#r2-object-table");
  table.innerHTML = state.r2Objects.length
    ? state.r2Objects.map((object) => `<tr><td><strong class="mono">${escapeHtml(object.key)}</strong><small>${escapeHtml(shortId(object.sha256, 18))}</small></td><td>${escapeHtml(formatBytes(object.size))}</td><td><small>${escapeHtml(object.content_type || "application/octet-stream")}</small></td><td><small>${escapeHtml(new Date(object.uploaded_at_ms).toLocaleString("zh-CN"))}</small></td><td><div class="table-actions"><button class="mini-button" data-r2-action="download" data-r2-key="${escapeHtml(object.key)}">下载</button><button class="mini-button danger" data-r2-action="delete" data-r2-key="${escapeHtml(object.key)}">删除</button></div></td></tr>`).join("")
    : '<tr><td colspan="5" class="empty-state">bucket 中暂无对象。</td></tr>';
  $("#r2-load-more").classList.toggle("hidden", !state.r2Cursor);
}

async function loadR2Objects({ append = false } = {}) {
  if (!state.r2Active) return;
  try {
    const query = new URLSearchParams({
      prefix: $("#r2-object-prefix").value,
      limit: "100",
    });
    if (append && state.r2Cursor) query.set("cursor", state.r2Cursor);
    const data = await api(`/api/r2/objects/${encodeURIComponent(state.r2Active)}?${query}`);
    state.r2Objects = append ? [...state.r2Objects, ...(data.objects || [])] : (data.objects || []);
    state.r2Cursor = data.cursor || null;
    renderR2Objects();
  } catch (error) {
    toast(error.message, true);
  }
}

async function uploadR2Object(event) {
  event.preventDefault();
  const file = $("#r2-object-file").files?.[0];
  const key = $("#r2-object-key").value;
  if (!file || !state.r2Active) return;
  if (file.size > 63 * 1024 * 1024) {
    toast("单次上传最大为 63 MiB", true);
    return;
  }
  try {
    await api(`/api/r2/object/${encodeURIComponent(state.r2Active)}/${encodeURIComponent(key)}`, {
      method: "PUT",
      headers: { "content-type": file.type || "application/octet-stream" },
      body: file,
    });
    toast(`已上传 ${key}`);
    $("#r2-object-file").value = "";
    await loadR2Objects();
  } catch (error) {
    toast(error.message, true);
  }
}

async function downloadR2Object(key) {
  if (!state.r2Active) return;
  setBusy(true);
  try {
    const headers = new Headers();
    if (consoleMode === "local") headers.set("x-rf-console-token", token);
    const response = await fetch(`/api/r2/object/${encodeURIComponent(state.r2Active)}/${encodeURIComponent(key)}`, { headers });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload.error || `下载失败（HTTP ${response.status}）`);
    }
    const url = URL.createObjectURL(await response.blob());
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = key.split("/").pop() || "object";
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (error) {
    toast(error.message, true);
  } finally {
    setBusy(false);
  }
}

async function deleteR2Object(key) {
  if (!state.r2Active || !window.confirm(`要删除对象“${key}”吗？`)) return;
  try {
    await api(`/api/r2/object/${encodeURIComponent(state.r2Active)}/${encodeURIComponent(key)}`, { method: "DELETE" });
    toast(`已删除 ${key}`);
    await loadR2Objects();
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteR2Bucket() {
  const name = state.r2Active;
  if (!name || !window.confirm(`要删除 R2 bucket“${name}”吗？对象字节将等待安全回收。`)) return;
  try {
    const result = await api(`/api/r2/buckets/${encodeURIComponent(name)}`, { method: "DELETE" });
    const complete = async () => {
      state.r2Active = null;
      fillR2BucketForm(null);
      await loadOverview({ quiet: true });
      await loadR2({ quiet: true });
    };
    if (result.pending_approval) {
      showApproval(result, `批准后，R2 bucket ${name} 将写入可验证的墓碑版本。`, complete);
    } else {
      toast(`R2 bucket ${name} 已删除`);
      await complete();
    }
  } catch (error) {
    toast(error.message, true);
  }
}

function queueStatsCopy(stats) {
  if (!stats) return "统计正在收敛";
  return `${stats.ready || 0} 待处理 · ${stats.inflight || 0} 处理中 · ${stats.dead_letters || 0} 死信`;
}

function renderQueues() {
  $("#queue-count").textContent = `${state.queues.length} 个队列`;
  $("#queue-nav-count").textContent = String(state.queues.length);
  const list = $("#queue-list");
  list.classList.toggle("empty-state", state.queues.length === 0);
  list.innerHTML = state.queues.length
    ? state.queues.map((queue) => {
      const active = queue.name === state.queueActive ? " active" : "";
      const consumer = queue.spec?.consumer_worker || "未绑定消费者";
      return `<button class="database-item${active}" type="button" data-queue="${escapeHtml(queue.name)}"><span><strong>${escapeHtml(queue.name)}</strong><small>${escapeHtml(consumer)} · ${escapeHtml(queueStatsCopy(queue.stats))}</small></span><span>${queue.spec?.suspended ? "已暂停" : "打开 →"}</span></button>`;
    }).join("")
    : "暂无队列。";
}

function fillQueueForm(queue) {
  const spec = queue?.spec || {};
  $("#queue-name").value = queue?.name || "";
  $("#queue-description").value = spec.description || "";
  $("#queue-consumer").value = spec.consumer_worker || "";
  $("#queue-batch-size").value = spec.batch_size ?? 10;
  $("#queue-max-wait").value = spec.max_wait_ms ?? 5000;
  $("#queue-max-retries").value = spec.max_retries ?? 3;
  $("#queue-visibility").value = spec.visibility_timeout_ms ?? 120000;
  $("#queue-retention").value = spec.retention_seconds ?? 604800;
  $("#queue-dead-target").value = spec.dead_letter_queue || "";
  $("#queue-suspended").checked = Boolean(spec.suspended);
}

async function loadQueues({ quiet = false } = {}) {
  try {
    const data = await api("/api/queues");
    state.queues = data.queues || [];
    if (state.queueActive && !state.queues.some((queue) => queue.name === state.queueActive)) {
      state.queueActive = null;
      state.queueDeadLetters = [];
      $("#queue-active-name").textContent = "请选择队列";
      $("#queue-summary").textContent = "选择左侧队列后，可发送测试消息并检查死信。";
      $("#queue-send-form").classList.add("hidden");
      $("#queue-delete").classList.add("hidden");
    }
    renderQueues();
    if (!quiet) toast("队列已刷新");
  } catch (error) {
    if (!quiet) toast(error.message, true);
  }
}

async function selectQueue(name) {
  const queue = state.queues.find((item) => item.name === name);
  if (!queue) return;
  state.queueActive = name;
  fillQueueForm(queue);
  $("#queue-active-name").textContent = name;
  $("#queue-summary").textContent = `${queueStatsCopy(queue.stats)} · 批量 ${queue.spec.batch_size} · 最多重试 ${queue.spec.max_retries} 次`;
  $("#queue-send-form").classList.remove("hidden");
  $("#queue-delete").classList.remove("hidden");
  renderQueues();
  await loadQueueDeadLetters();
}

async function saveQueue(event) {
  event.preventDefault();
  const payload = {
    name: $("#queue-name").value.trim(),
    description: $("#queue-description").value.trim(),
    consumer_worker: $("#queue-consumer").value.trim() || null,
    batch_size: Number($("#queue-batch-size").value),
    max_wait_ms: Number($("#queue-max-wait").value),
    max_retries: Number($("#queue-max-retries").value),
    visibility_timeout_ms: Number($("#queue-visibility").value),
    retention_seconds: Number($("#queue-retention").value),
    dead_letter_queue: $("#queue-dead-target").value.trim() || null,
    suspended: $("#queue-suspended").checked,
  };
  try {
    const result = await api("/api/queues", { method: "POST", body: JSON.stringify(payload) });
    const complete = async () => {
      await loadQueues({ quiet: true });
      await selectQueue(payload.name);
    };
    if (result.pending_approval) {
      showApproval(result, `批准后，队列 ${payload.name} 的签名配置将传播到集群。`, complete);
    } else {
      toast(`队列 ${payload.name} 已保存`);
      await complete();
    }
  } catch (error) {
    toast(error.message, true);
  }
}

async function sendQueueMessage(event) {
  event.preventDefault();
  if (!state.queueActive) return;
  let body;
  try {
    body = JSON.parse($("#queue-message-body").value);
  } catch (error) {
    toast(`消息体不是有效 JSON：${error.message}`, true);
    return;
  }
  try {
    const result = await api(`/api/queues/${encodeURIComponent(state.queueActive)}/messages`, {
      method: "POST",
      body: JSON.stringify({ messages: [{ body, delay_seconds: Number($("#queue-message-delay").value || 0) }] }),
    });
    toast(`消息已入队：${shortId(result.message_ids?.[0], 16)}`);
    await loadQueues({ quiet: true });
    await selectQueue(state.queueActive);
  } catch (error) {
    toast(error.message, true);
  }
}

function renderQueueDeadLetters() {
  const list = $("#queue-dead-list");
  list.classList.toggle("empty-state", state.queueDeadLetters.length === 0);
  list.innerHTML = state.queueDeadLetters.length
    ? state.queueDeadLetters.map((item) => `<article class="build-row failed"><span class="pipeline-state failed"></span><div><strong>${escapeHtml(shortId(item.id, 22))}</strong><small>${escapeHtml(new Date(item.dead_letter_at_ms).toLocaleString("zh-CN"))} · 尝试 ${escapeHtml(item.attempts)} 次</small><code>${escapeHtml(JSON.stringify(item.body))}</code></div><div><small>${escapeHtml(item.last_error || "处理程序请求重试")}</small></div><button class="mini-button" data-queue-redrive="${escapeHtml(item.id)}">重新入队</button></article>`).join("")
    : "暂无死信。";
}

async function loadQueueDeadLetters() {
  if (!state.queueActive) {
    state.queueDeadLetters = [];
    renderQueueDeadLetters();
    return;
  }
  try {
    const data = await api(`/api/queues/${encodeURIComponent(state.queueActive)}/dead?limit=100`);
    state.queueDeadLetters = data.dead_letters || [];
    renderQueueDeadLetters();
  } catch (error) {
    toast(error.message, true);
  }
}

async function redriveQueueMessage(id) {
  if (!state.queueActive) return;
  try {
    await api(`/api/queues/${encodeURIComponent(state.queueActive)}/dead/${encodeURIComponent(id)}/redrive`, { method: "POST", body: "{}" });
    toast("死信已重新入队");
    await loadQueueDeadLetters();
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteQueue() {
  const name = state.queueActive;
  if (!name || !window.confirm(`要删除队列“${name}”吗？已签名的历史与数据库将保留供审计。`)) return;
  try {
    const result = await api(`/api/queues/${encodeURIComponent(name)}`, { method: "DELETE" });
    const complete = async () => {
      state.queueActive = null;
      fillQueueForm(null);
      await loadQueues({ quiet: true });
    };
    if (result.pending_approval) {
      showApproval(result, `批准后，队列 ${name} 将写入可验证的墓碑版本。`, complete);
    } else {
      toast(`队列 ${name} 已删除`);
      await complete();
    }
  } catch (error) {
    toast(error.message, true);
  }
}

function analyticsStatsCopy(stats) {
  if (!stats) return "统计正在收敛";
  return `${stats.last_hour || 0} / 小时 · ${stats.last_24_hours || 0} / 24 小时 · 共 ${stats.total || 0}`;
}

function renderAnalyticsDatasets() {
  $("#analytics-count").textContent = `${state.analyticsDatasets.length} 个数据集`;
  $("#analytics-nav-count").textContent = String(state.analyticsDatasets.length);
  const list = $("#analytics-list");
  list.classList.toggle("empty-state", state.analyticsDatasets.length === 0);
  list.innerHTML = state.analyticsDatasets.length
    ? state.analyticsDatasets.map((dataset) => {
      const active = dataset.name === state.analyticsActive ? " active" : "";
      const retention = dataset.spec?.retention_days ? `保留 ${dataset.spec.retention_days} 天` : "永久保留";
      return `<button class="database-item${active}" type="button" data-analytics="${escapeHtml(dataset.name)}"><span><strong>${escapeHtml(dataset.name)}</strong><small>${escapeHtml(retention)} · ${escapeHtml(analyticsStatsCopy(dataset.stats))}</small></span><span>打开 →</span></button>`;
    }).join("")
    : "暂无 Analytics 数据集。";
}

function fillAnalyticsForm(dataset) {
  $("#analytics-name").value = dataset?.name || "";
  $("#analytics-description").value = dataset?.spec?.description || "";
  $("#analytics-retention").value = dataset?.spec?.retention_days || "";
}

function renderAnalyticsEvents() {
  const list = $("#analytics-events");
  list.classList.toggle("empty-state", state.analyticsEvents.length === 0);
  list.innerHTML = state.analyticsEvents.length
    ? state.analyticsEvents.map((event) => `<article class="build-row"><span class="pipeline-state success"></span><div><strong>${escapeHtml(new Date(event.ts_ms).toLocaleString("zh-CN"))}</strong><small>${escapeHtml(shortId(event.id, 24))}</small><code>blobs ${escapeHtml(JSON.stringify(event.blobs))}</code></div><div><code>doubles ${escapeHtml(JSON.stringify(event.doubles))}</code><code>indexes ${escapeHtml(JSON.stringify(event.indexes))}</code></div></article>`).join("")
    : "暂无事件。";
}

function renderAnalyticsGroups() {
  const list = $("#analytics-groups");
  list.classList.toggle("empty-state", state.analyticsGroups.length === 0);
  list.innerHTML = state.analyticsGroups.length
    ? state.analyticsGroups.map((group) => `<article class="build-row"><span class="pipeline-state success"></span><div><strong>${escapeHtml(JSON.stringify(group.key))}</strong><small>${escapeHtml(group.count)} 个事件</small></div><div><small>总和 ${escapeHtml(group.sum ?? "—")} · 平均 ${escapeHtml(group.average ?? "—")}</small><small>范围 ${escapeHtml(group.minimum ?? "—")} ～ ${escapeHtml(group.maximum ?? "—")}</small></div></article>`).join("")
    : "暂无聚合结果。";
}

async function loadAnalytics({ quiet = false } = {}) {
  try {
    const data = await api("/api/analytics");
    state.analyticsDatasets = data.datasets || [];
    if (state.analyticsActive && !state.analyticsDatasets.some((item) => item.name === state.analyticsActive)) {
      state.analyticsActive = null;
      state.analyticsEvents = [];
      state.analyticsGroups = [];
      $("#analytics-active-name").textContent = "请选择数据集";
      $("#analytics-summary").textContent = "选择左侧数据集后，可查看聚合结果与最近事件。";
      $("#analytics-write-form").classList.add("hidden");
      $("#analytics-delete").classList.add("hidden");
      $("#analytics-hour").textContent = "—";
      $("#analytics-day").textContent = "—";
      $("#analytics-total").textContent = "—";
      renderAnalyticsEvents();
      renderAnalyticsGroups();
    }
    renderAnalyticsDatasets();
    if (!quiet) toast("Analytics 数据集已刷新");
  } catch (error) {
    if (!quiet) toast(error.message, true);
  }
}

async function loadAnalyticsGroups() {
  if (!state.analyticsActive) {
    state.analyticsGroups = [];
    renderAnalyticsGroups();
    return;
  }
  const kind = $("#analytics-group-kind").value;
  const dimensionIndex = Number($("#analytics-group-index").value || 0);
  const doubleRaw = $("#analytics-double-index").value.trim();
  const params = new URLSearchParams({
    dimension: kind,
    dimension_index: String(dimensionIndex),
    since: String(Date.now() - 24 * 60 * 60 * 1000),
    limit: "20",
  });
  if (doubleRaw !== "") params.set("double_index", doubleRaw);
  const data = await api(`/api/analytics/${encodeURIComponent(state.analyticsActive)}/group?${params}`);
  state.analyticsGroups = data.groups || [];
  renderAnalyticsGroups();
}

async function selectAnalytics(name) {
  const dataset = state.analyticsDatasets.find((item) => item.name === name);
  if (!dataset) return;
  state.analyticsActive = name;
  fillAnalyticsForm(dataset);
  $("#analytics-active-name").textContent = name;
  $("#analytics-summary").textContent = dataset.spec?.description || analyticsStatsCopy(dataset.stats);
  $("#analytics-write-form").classList.remove("hidden");
  $("#analytics-delete").classList.remove("hidden");
  renderAnalyticsDatasets();
  try {
    const [stats, events] = await Promise.all([
      api(`/api/analytics/${encodeURIComponent(name)}/stats`),
      api(`/api/analytics/${encodeURIComponent(name)}/events?limit=100`),
    ]);
    if (state.analyticsActive !== name) return;
    $("#analytics-hour").textContent = String(stats.last_hour || 0);
    $("#analytics-day").textContent = String(stats.last_24_hours || 0);
    $("#analytics-total").textContent = String(stats.total || 0);
    state.analyticsEvents = events.events || [];
    renderAnalyticsEvents();
    await loadAnalyticsGroups();
  } catch (error) {
    toast(error.message, true);
  }
}

async function saveAnalytics(event) {
  event.preventDefault();
  const retention = $("#analytics-retention").value.trim();
  const payload = {
    name: $("#analytics-name").value.trim(),
    description: $("#analytics-description").value.trim(),
    retention_days: retention === "" ? null : Number(retention),
  };
  try {
    const result = await api("/api/analytics", { method: "POST", body: JSON.stringify(payload) });
    const complete = async () => {
      await loadAnalytics({ quiet: true });
      await selectAnalytics(payload.name);
    };
    if (result.pending_approval) {
      showApproval(result, `批准后，Analytics 数据集 ${payload.name} 的签名配置将传播到集群。`, complete);
    } else {
      toast(`Analytics 数据集 ${payload.name} 已保存`);
      await complete();
    }
  } catch (error) {
    toast(error.message, true);
  }
}

async function writeAnalyticsPoint(event) {
  event.preventDefault();
  if (!state.analyticsActive) return;
  let point;
  try {
    point = JSON.parse($("#analytics-point").value);
  } catch (error) {
    toast(`数据点不是有效 JSON：${error.message}`, true);
    return;
  }
  try {
    await api(`/api/analytics/${encodeURIComponent(state.analyticsActive)}/events`, {
      method: "POST",
      body: JSON.stringify({ points: [point] }),
    });
    toast("Analytics 数据点已写入");
    await loadAnalytics({ quiet: true });
    await selectAnalytics(state.analyticsActive);
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteAnalytics() {
  const name = state.analyticsActive;
  if (!name || !window.confirm(`要删除 Analytics 数据集“${name}”吗？已签名的历史与底层数据将保留供审计。`)) return;
  try {
    const result = await api(`/api/analytics/${encodeURIComponent(name)}`, { method: "DELETE" });
    const complete = async () => {
      state.analyticsActive = null;
      fillAnalyticsForm(null);
      await loadAnalytics({ quiet: true });
    };
    if (result.pending_approval) {
      showApproval(result, `批准后，Analytics 数据集 ${name} 将写入可验证的墓碑版本。`, complete);
    } else {
      toast(`Analytics 数据集 ${name} 已删除`);
      await complete();
    }
  } catch (error) {
    toast(error.message, true);
  }
}

function pipelineStatusCopy(status) {
  if (!status) return "状态正在收敛";
  return `${status.queued_events || 0} 待处理 · ${status.completed_batches || 0} 成功 · ${status.failed_batches || 0} 失败`;
}

function renderPipelines() {
  $("#pipeline-count").textContent = `${state.pipelines.length} 条 Pipeline`;
  $("#pipeline-nav-count").textContent = String(state.pipelines.length);
  const list = $("#pipeline-list");
  list.classList.toggle("empty-state", state.pipelines.length === 0);
  list.innerHTML = state.pipelines.length
    ? state.pipelines.map((pipeline) => {
      const active = pipeline.name === state.pipelineActive ? " active" : "";
      const stateCopy = pipeline.spec?.suspended ? "已暂停" : pipelineStatusCopy(pipeline.status);
      return `<button class="database-item${active}" type="button" data-pipeline="${escapeHtml(pipeline.name)}"><span><strong>${escapeHtml(pipeline.name)}</strong><small>${escapeHtml(pipeline.spec?.output_bucket || "未配置 bucket")} · ${escapeHtml(stateCopy)}</small></span><span>${pipeline.spec?.suspended ? "已暂停" : "打开 →"}</span></button>`;
    }).join("")
    : "暂无 Pipeline。";
}

function fillPipelineForm(pipeline) {
  const spec = pipeline?.spec || {};
  $("#pipeline-name").value = pipeline?.name || "";
  $("#pipeline-description").value = spec.description || "";
  $("#pipeline-bucket").value = spec.output_bucket || "";
  $("#pipeline-key-template").value = spec.output_key_template || "{pipeline}/year={yyyy}/month={mm}/day={dd}/hour={hh}/{agent}-{batchId}.jsonl.gz";
  $("#pipeline-batch-mib").value = Number(spec.batch_max_bytes || 64 * 1024 * 1024) / 1024 / 1024;
  $("#pipeline-batch-seconds").value = spec.batch_max_seconds || 60;
  $("#pipeline-hostnames").value = (spec.hostnames || []).join("\n");
  $("#pipeline-schema").value = spec.schema == null ? "" : JSON.stringify(spec.schema, null, 2);
  $("#pipeline-suspended").checked = Boolean(spec.suspended);
  $("#pipeline-suspend-reason").value = spec.suspend_reason || "";
}

function renderPipelineTokens(pipeline) {
  const tokens = pipeline?.spec?.tokens || [];
  const list = $("#pipeline-token-list");
  list.classList.toggle("empty-state", tokens.length === 0);
  list.innerHTML = tokens.length
    ? tokens.map((token) => `<article class="build-row"><span class="pipeline-state success"></span><div><strong>${escapeHtml(token.label || "未命名令牌")}</strong><small>尾号 ${escapeHtml(token.last_four)} · ${escapeHtml(new Date(token.created_at_ms).toLocaleString("zh-CN"))}</small><code>${escapeHtml(token.id)}</code></div><button class="mini-button danger" data-pipeline-token-revoke="${escapeHtml(token.id)}">撤销</button></article>`).join("")
    : "暂无接收令牌。";
}

function renderPipelineBatches() {
  const list = $("#pipeline-batches");
  list.classList.toggle("empty-state", state.pipelineBatches.length === 0);
  list.innerHTML = state.pipelineBatches.length
    ? state.pipelineBatches.map((batch) => `<article class="build-row ${batch.state === "failed" ? "failed" : "success"}"><span class="pipeline-state ${batch.state === "failed" ? "failed" : "success"}"></span><div><strong>${escapeHtml(batch.object_key || batch.id)}</strong><small>${escapeHtml(batch.event_count)} 个事件 · ${escapeHtml(formatBytes(batch.compressed_bytes))} gzip · ${escapeHtml(new Date(batch.created_at_ms).toLocaleString("zh-CN"))}</small><code>${escapeHtml(batch.sha256 || batch.id)}</code></div><div><span class="badge">${batch.state === "completed" ? "已输出" : "失败"}</span><small>${escapeHtml(batch.error || "")}</small></div></article>`).join("")
    : "暂无输出批次。";
}

async function loadPipelines({ quiet = false } = {}) {
  try {
    const data = await api("/api/pipelines");
    state.pipelines = data.pipelines || [];
    if (state.pipelineActive && !state.pipelines.some((item) => item.name === state.pipelineActive)) {
      state.pipelineActive = null;
      state.pipelineBatches = [];
      $("#pipeline-active-name").textContent = "请选择 Pipeline";
      $("#pipeline-endpoint").textContent = "选择后显示接收端点和运行状态。";
      $("#pipeline-token-form").classList.add("hidden");
      $("#pipeline-ingest-form").classList.add("hidden");
      $("#pipeline-delete").classList.add("hidden");
      $("#pipeline-flush").classList.add("hidden");
      renderPipelineBatches();
      renderPipelineTokens(null);
    }
    renderPipelines();
    if (!quiet) toast("Pipeline 已刷新");
  } catch (error) {
    if (!quiet) toast(error.message, true);
  }
}

async function selectPipeline(name) {
  const pipeline = state.pipelines.find((item) => item.name === name);
  if (!pipeline) return;
  if (state.pipelineActive !== name) {
    $("#pipeline-new-token").textContent = "";
    $("#pipeline-token-reveal").classList.add("hidden");
  }
  state.pipelineActive = name;
  fillPipelineForm(pipeline);
  renderPipelines();
  renderPipelineTokens(pipeline);
  $("#pipeline-active-name").textContent = name;
  const endpointHost = pipeline.hostnames?.[0];
  $("#pipeline-endpoint").textContent = endpointHost
    ? `接收端点：${location.protocol}//${endpointHost}/send`
    : "尚未配置可访问的接收域名；Worker 绑定仍可在节点内写入。";
  $("#pipeline-token-form").classList.remove("hidden");
  $("#pipeline-ingest-form").classList.remove("hidden");
  $("#pipeline-delete").classList.remove("hidden");
  $("#pipeline-flush").classList.remove("hidden");
  try {
    const [status, batches] = await Promise.all([
      api(`/api/pipelines/${encodeURIComponent(name)}/status`),
      api(`/api/pipelines/${encodeURIComponent(name)}/batches?limit=100`),
    ]);
    if (state.pipelineActive !== name) return;
    $("#pipeline-queued-events").textContent = String(status.queued_events || 0);
    $("#pipeline-queued-bytes").textContent = formatBytes(status.queued_bytes || 0);
    $("#pipeline-completed").textContent = String(status.completed_batches || 0);
    $("#pipeline-failed").textContent = String(status.failed_batches || 0);
    state.pipelineBatches = batches.batches || [];
    renderPipelineBatches();
  } catch (error) {
    toast(error.message, true);
  }
}

async function savePipeline(event) {
  event.preventDefault();
  let schema = null;
  try {
    const raw = $("#pipeline-schema").value.trim();
    if (raw) schema = JSON.parse(raw);
  } catch (error) {
    toast(`JSON Schema 不是有效 JSON：${error.message}`, true);
    return;
  }
  const payload = {
    name: $("#pipeline-name").value.trim(),
    description: $("#pipeline-description").value.trim(),
    output_bucket: $("#pipeline-bucket").value.trim(),
    output_key_template: $("#pipeline-key-template").value.trim(),
    batch_max_bytes: Math.round(Number($("#pipeline-batch-mib").value) * 1024 * 1024),
    batch_max_seconds: Number($("#pipeline-batch-seconds").value),
    schema,
    suspended: $("#pipeline-suspended").checked,
    suspend_reason: $("#pipeline-suspend-reason").value.trim(),
    hostnames: $("#pipeline-hostnames").value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean),
  };
  try {
    const result = await api("/api/pipelines", { method: "POST", body: JSON.stringify(payload) });
    const complete = async () => {
      await loadPipelines({ quiet: true });
      await selectPipeline(payload.name);
    };
    if (result.pending_approval) {
      showApproval(result, `批准后，Pipeline ${payload.name} 的签名配置将传播到集群。`, complete);
    } else {
      toast(`Pipeline ${payload.name} 已保存`);
      await complete();
    }
  } catch (error) {
    toast(error.message, true);
  }
}

async function mintPipelineToken(event) {
  event.preventDefault();
  if (!state.pipelineActive) return;
  try {
    const result = await api(`/api/pipelines/${encodeURIComponent(state.pipelineActive)}/tokens`, {
      method: "POST",
      body: JSON.stringify({ label: $("#pipeline-token-label").value.trim() }),
    });
    $("#pipeline-new-token").textContent = result.token;
    $("#pipeline-token-reveal").classList.remove("hidden");
    $("#pipeline-token-label").value = "";
    const complete = async () => {
      await loadPipelines({ quiet: true });
      await selectPipeline(state.pipelineActive);
    };
    if (result.pending_approval) {
      showApproval(result, "批准后令牌才会生效；当前明文仍只显示这一次。", complete);
    } else {
      toast("Pipeline 接收令牌已创建，请立即保存");
      await complete();
    }
  } catch (error) {
    toast(error.message, true);
  }
}

async function revokePipelineToken(id) {
  if (!state.pipelineActive || !window.confirm("要撤销这个 Pipeline 接收令牌吗？使用它的采集器会立即失去访问权限。")) return;
  try {
    const result = await api(`/api/pipelines/${encodeURIComponent(state.pipelineActive)}/tokens/${encodeURIComponent(id)}`, { method: "DELETE" });
    const complete = async () => {
      await loadPipelines({ quiet: true });
      await selectPipeline(state.pipelineActive);
    };
    if (result.pending_approval) showApproval(result, "批准后该接收令牌将失效。", complete);
    else await complete();
  } catch (error) {
    toast(error.message, true);
  }
}

async function ingestPipelineEvents(event) {
  event.preventDefault();
  if (!state.pipelineActive) return;
  let events;
  try {
    events = JSON.parse($("#pipeline-events").value);
    if (!Array.isArray(events)) events = [events];
  } catch (error) {
    toast(`事件不是有效 JSON：${error.message}`, true);
    return;
  }
  try {
    const result = await api(`/api/pipelines/${encodeURIComponent(state.pipelineActive)}/events`, {
      method: "POST",
      body: JSON.stringify({ events }),
    });
    toast(`已接收 ${result.accepted} 个事件`);
    await selectPipeline(state.pipelineActive);
  } catch (error) {
    toast(error.message, true);
  }
}

async function flushPipeline() {
  if (!state.pipelineActive) return;
  try {
    const result = await api(`/api/pipelines/${encodeURIComponent(state.pipelineActive)}/flush`, { method: "POST", body: "{}" });
    toast(result.batch ? `批次 ${shortId(result.batch.id, 18)} 已输出` : "当前没有待刷新的事件");
    await loadPipelines({ quiet: true });
    await selectPipeline(state.pipelineActive);
  } catch (error) {
    toast(error.message, true);
  }
}

async function deletePipeline() {
  const name = state.pipelineActive;
  if (!name || !window.confirm(`要删除 Pipeline“${name}”吗？批次审计与 R2 对象不会被删除。`)) return;
  try {
    const result = await api(`/api/pipelines/${encodeURIComponent(name)}`, { method: "DELETE" });
    const complete = async () => {
      state.pipelineActive = null;
      fillPipelineForm(null);
      await loadPipelines({ quiet: true });
    };
    if (result.pending_approval) showApproval(result, `批准后，Pipeline ${name} 将写入可验证的墓碑版本。`, complete);
    else await complete();
  } catch (error) {
    toast(error.message, true);
  }
}

function workflowStatusLabel(status) {
  return {
    queued: "已排队",
    running: "运行中",
    waiting: "等待中",
    paused: "已暂停",
    complete: "已完成",
    failed: "失败",
    terminated: "已终止",
    ok: "成功",
    slept: "已睡眠",
    pending: "执行中",
  }[status] || status || "未知";
}

function workflowStatusClass(status) {
  if (status === "complete" || status === "ok") return "success";
  if (status === "failed" || status === "terminated") return "failed";
  return "active";
}

function updateWorkflowWorkerOptions(selected = "") {
  const workers = state.overview?.workers || [];
  const select = $("#workflow-worker");
  select.innerHTML = `<option value="">请选择 Worker</option>${workers.map((worker) => `<option value="${escapeHtml(worker.name)}">${escapeHtml(worker.name)} · v${escapeHtml(worker.version)}</option>`).join("")}`;
  select.value = selected;
}

function fillWorkflowForm(workflow) {
  const spec = workflow?.spec || {};
  $("#workflow-name").value = workflow?.name || "";
  updateWorkflowWorkerOptions(spec.worker || "");
  $("#workflow-entrypoint").value = spec.entrypoint || "MyWorkflow";
  $("#workflow-description").value = spec.description || "";
  $("#workflow-retention").value = spec.retention_days || 30;
  $("#workflow-retries").value = spec.instance_retries ?? 3;
  $("#workflow-timeout").value = spec.instance_timeout_seconds || 1500;
  $("#workflow-suspended").checked = Boolean(spec.suspended);
  $("#workflow-suspend-reason").value = spec.suspend_reason || "";
}

function renderWorkflows() {
  $("#workflow-count").textContent = `${state.workflows.length} 个 Workflow`;
  $("#workflow-nav-count").textContent = String(state.workflows.length);
  const list = $("#workflow-list");
  list.classList.toggle("empty-state", state.workflows.length === 0);
  list.innerHTML = state.workflows.length
    ? state.workflows.map((workflow) => {
      const stats = workflow.stats || {};
      const active = workflow.name === state.workflowActive ? " active" : "";
      const copy = workflow.spec?.suspended
        ? "已暂停"
        : `${Number(stats.queued || 0) + Number(stats.running || 0)} 活跃 · ${stats.waiting || 0} 等待`;
      return `<button class="database-item${active}" type="button" data-workflow="${escapeHtml(workflow.name)}"><span><strong>${escapeHtml(workflow.name)}</strong><small>${escapeHtml(workflow.spec?.worker || "未配置 Worker")} · ${escapeHtml(copy)}</small></span><span>${workflow.spec?.suspended ? "已暂停" : "打开 →"}</span></button>`;
    }).join("")
    : "暂无 Workflow。";
}

async function loadWorkflows({ quiet = false } = {}) {
  try {
    const data = await api("/api/workflows");
    state.workflows = data.workflows || [];
    if (state.workflowActive && !state.workflows.some((item) => item.name === state.workflowActive)) {
      state.workflowActive = null;
      state.workflowInstances = [];
      state.workflowInstanceActive = null;
      $("#workflow-active-name").textContent = "请选择 Workflow";
      $("#workflow-trigger-form").classList.add("hidden");
      $("#workflow-delete").classList.add("hidden");
      $("#workflow-instance-panel").classList.add("hidden");
    }
    updateWorkflowWorkerOptions($("#workflow-worker").value);
    renderWorkflows();
    if (!quiet) toast("Workflow 已刷新");
  } catch (error) {
    if (!quiet) toast(error.message, true);
  }
}

function renderWorkflowInstances() {
  const list = $("#workflow-instances");
  list.classList.toggle("empty-state", state.workflowInstances.length === 0);
  list.innerHTML = state.workflowInstances.length
    ? state.workflowInstances.map((instance) => `<button class="build-row" type="button" data-workflow-instance="${escapeHtml(instance.id)}"><span class="pipeline-state ${workflowStatusClass(instance.status)}"></span><div><strong>${escapeHtml(instance.instance_key || shortId(instance.id, 22))}</strong><small>${escapeHtml(new Date(instance.started_at_ms).toLocaleString("zh-CN"))}${instance.waiting_for ? ` · 等待 ${escapeHtml(instance.waiting_for)}` : ""}</small><code>${escapeHtml(instance.id)}</code></div><span class="badge">${escapeHtml(workflowStatusLabel(instance.status))}</span></button>`).join("")
    : "暂无实例。";
}

async function selectWorkflow(name) {
  const workflow = state.workflows.find((item) => item.name === name);
  if (!workflow) return;
  const workflowChanged = state.workflowActive !== name;
  state.workflowActive = name;
  if (workflowChanged) state.workflowInstanceActive = null;
  fillWorkflowForm(workflow);
  renderWorkflows();
  $("#workflow-active-name").textContent = name;
  $("#workflow-summary").textContent = `${workflow.spec.worker} · ${workflow.spec.entrypoint} · 定义 v${workflow.version}`;
  $("#workflow-trigger-form").classList.remove("hidden");
  $("#workflow-delete").classList.remove("hidden");
  if (workflowChanged) $("#workflow-instance-panel").classList.add("hidden");
  const stats = workflow.stats || {};
  $("#workflow-active-count").textContent = String(Number(stats.queued || 0) + Number(stats.running || 0));
  $("#workflow-waiting-count").textContent = String(stats.waiting || 0);
  $("#workflow-complete-count").textContent = String(stats.complete || 0);
  $("#workflow-failed-count").textContent = String(stats.failed || 0);
  await loadWorkflowInstances();
}

async function loadWorkflowInstances() {
  if (!state.workflowActive) return;
  try {
    const data = await api(`/api/workflows/${encodeURIComponent(state.workflowActive)}/instances?limit=100`);
    state.workflowInstances = data.instances || [];
    renderWorkflowInstances();
    if (state.workflowInstanceActive && state.workflowInstances.some((item) => item.id === state.workflowInstanceActive)) {
      await openWorkflowInstance(state.workflowInstanceActive);
    }
  } catch (error) {
    toast(error.message, true);
  }
}

function renderWorkflowSteps(steps) {
  const list = $("#workflow-steps");
  list.classList.toggle("empty-state", steps.length === 0);
  list.innerHTML = steps.length
    ? steps.map((step) => `<article class="build-row ${step.status === "failed" ? "failed" : ""}"><span class="pipeline-state ${workflowStatusClass(step.status)}"></span><div><strong>${escapeHtml(step.seq)}. ${escapeHtml(step.name)}</strong><small>${escapeHtml(step.kind)} · ${escapeHtml(workflowStatusLabel(step.status))} · ${escapeHtml(step.attempts)} 次尝试${step.wake_at_ms ? ` · ${escapeHtml(new Date(step.wake_at_ms).toLocaleString("zh-CN"))} 唤醒` : ""}</small><code>${escapeHtml(step.error || (step.result == null ? "" : JSON.stringify(step.result)))}</code></div></article>`).join("")
    : "暂无步骤。";
}

function renderWorkflowEvents(events) {
  const labels = {
    created: "实例已创建", advance_claimed: "节点取得推进租约", step_complete: "步骤已提交",
    step_failed: "步骤失败", sleep: "进入耐久睡眠", signal_wait: "等待外部信号",
    signal_received: "收到外部信号", signal_ready: "信号已就绪，重新排队", signal_delivered: "信号已交付", complete: "实例完成",
    failed: "实例失败", paused: "实例已暂停", resumed: "实例已恢复", terminated: "实例已终止",
    restarted: "实例已重启", system_retry: "系统故障后重试",
  };
  const list = $("#workflow-events");
  list.classList.toggle("empty-state", events.length === 0);
  list.innerHTML = events.length
    ? events.slice().reverse().map((event) => `<article class="build-row"><span class="pipeline-state active"></span><div><strong>${escapeHtml(labels[event.kind] || event.kind)}</strong><small>${escapeHtml(new Date(event.created_at_ms).toLocaleString("zh-CN"))} · 序号 ${escapeHtml(event.seq)}</small><code>${escapeHtml(JSON.stringify(event.detail || {}))}</code></div></article>`).join("")
    : "暂无事件。";
}

async function openWorkflowInstance(id) {
  if (!state.workflowActive) return;
  state.workflowInstanceActive = id;
  try {
    const data = await api(`/api/workflows/${encodeURIComponent(state.workflowActive)}/instances/${encodeURIComponent(id)}`);
    if (state.workflowInstanceActive !== id) return;
    const instance = data.instance;
    $("#workflow-instance-panel").classList.remove("hidden");
    $("#workflow-instance-title").textContent = instance.instance_key || shortId(instance.id, 28);
    $("#workflow-instance-status").textContent = workflowStatusLabel(instance.status);
    $("#workflow-instance-meta").textContent = `${instance.id} · ${new Date(instance.started_at_ms).toLocaleString("zh-CN")}${instance.last_error ? ` · ${instance.last_error}` : ""}`;
    const actions = [];
    if (["queued", "running", "waiting"].includes(instance.status)) actions.push(["pause", "暂停"], ["terminate", "终止"]);
    if (instance.status === "paused") actions.push(["resume", "恢复"], ["terminate", "终止"]);
    if (["complete", "failed", "terminated"].includes(instance.status)) actions.push(["restart", "从耐久边界重启"]);
    $("#workflow-instance-actions").innerHTML = actions.map(([action, label]) => `<button class="${action === "terminate" ? "danger ghost" : "secondary"} compact" type="button" data-workflow-action="${action}">${label}</button>`).join("");
    $("#workflow-signal-form").classList.toggle("hidden", !["queued", "running", "waiting", "paused"].includes(instance.status));
    renderWorkflowSteps(data.steps || []);
    renderWorkflowEvents(data.events || []);
  } catch (error) {
    toast(error.message, true);
  }
}

async function saveWorkflow(event) {
  event.preventDefault();
  const payload = {
    name: $("#workflow-name").value.trim(), worker: $("#workflow-worker").value,
    entrypoint: $("#workflow-entrypoint").value.trim(), description: $("#workflow-description").value.trim(),
    retention_days: Number($("#workflow-retention").value), instance_retries: Number($("#workflow-retries").value),
    instance_timeout_seconds: Number($("#workflow-timeout").value), suspended: $("#workflow-suspended").checked,
    suspend_reason: $("#workflow-suspend-reason").value.trim(),
  };
  try {
    const result = await api("/api/workflows", { method: "POST", body: JSON.stringify(payload) });
    const complete = async () => { await loadWorkflows({ quiet: true }); await selectWorkflow(payload.name); };
    if (result.pending_approval) showApproval(result, `批准后，Workflow ${payload.name} 的签名定义将传播到集群。`, complete);
    else { toast(`Workflow ${payload.name} 已保存`); await complete(); }
  } catch (error) { toast(error.message, true); }
}

async function triggerWorkflow(event) {
  event.preventDefault();
  if (!state.workflowActive) return;
  let input;
  try { input = JSON.parse($("#workflow-input").value); }
  catch (error) { toast(`输入不是有效 JSON：${error.message}`, true); return; }
  try {
    const data = await api(`/api/workflows/${encodeURIComponent(state.workflowActive)}/instances`, {
      method: "POST", body: JSON.stringify({ instance_key: $("#workflow-instance-key").value.trim() || null, input }),
    });
    toast(`Workflow 实例 ${shortId(data.instance.id, 20)} 已触发`);
    await loadWorkflows({ quiet: true });
    await selectWorkflow(state.workflowActive);
    await openWorkflowInstance(data.instance.id);
  } catch (error) { toast(error.message, true); }
}

async function sendWorkflowSignal(event) {
  event.preventDefault();
  if (!state.workflowActive || !state.workflowInstanceActive) return;
  let payload;
  try { payload = JSON.parse($("#workflow-signal-payload").value); }
  catch (error) { toast(`信号负载不是有效 JSON：${error.message}`, true); return; }
  try {
    await api(`/api/workflows/${encodeURIComponent(state.workflowActive)}/instances/${encodeURIComponent(state.workflowInstanceActive)}/signal`, {
      method: "POST", body: JSON.stringify({ name: $("#workflow-signal-name").value.trim(), payload }),
    });
    toast("外部信号已持久化");
    await loadWorkflowInstances();
  } catch (error) { toast(error.message, true); }
}

async function runWorkflowAction(action) {
  if (!state.workflowActive || !state.workflowInstanceActive) return;
  const workflowName = state.workflowActive;
  const instanceId = state.workflowInstanceActive;
  if (action === "terminate" && !window.confirm("要终止这个 Workflow 实例吗？正在运行的推进结果将被丢弃。")) return;
  try {
    await api(`/api/workflows/${encodeURIComponent(workflowName)}/instances/${encodeURIComponent(instanceId)}/${action}`, { method: "POST", body: "{}" });
    toast(`Workflow 实例已${{ pause: "暂停", resume: "恢复", terminate: "终止", restart: "重启" }[action] || "更新"}`);
    await loadWorkflows({ quiet: true });
    await selectWorkflow(workflowName);
    await openWorkflowInstance(instanceId);
  } catch (error) { toast(error.message, true); }
}

async function deleteWorkflow() {
  const name = state.workflowActive;
  if (!name || !window.confirm(`要删除 Workflow“${name}”吗？定义会写入可验证墓碑，历史账本按保留策略清理。`)) return;
  try {
    const result = await api(`/api/workflows/${encodeURIComponent(name)}`, { method: "DELETE" });
    const complete = async () => { state.workflowActive = null; state.workflowInstanceActive = null; fillWorkflowForm(null); await loadWorkflows({ quiet: true }); };
    if (result.pending_approval) showApproval(result, `批准后，Workflow ${name} 将停止创建与推进实例。`, complete);
    else await complete();
  } catch (error) { toast(error.message, true); }
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
    $$("#deploy-form button, #source-form button, #kv-editor-form button, #d1-create-form button, #d1-exec-form button, #r2-bucket-form button, #r2-upload-form button, #r2-delete-bucket, #queue-form button, #queue-send-form button, #queue-delete, #analytics-form button, #analytics-write-form button, #analytics-delete, #pipeline-form button, #pipeline-token-form button, #pipeline-ingest-form button, #pipeline-flush, #pipeline-delete, #workflow-form button, #workflow-trigger-form button, #workflow-signal-form button, #workflow-delete, #project-domain-add-form button, #project-bindings-form button, #project-triggers-form button, #project-settings-form button, #project-source-form button, #project-redeploy, #project-delete")
      .forEach((button) => { button.disabled = state.session.read_only; });
    await loadOverview({ quiet: true });
    await loadWorkerOps();
    await loadKeys();
    await loadR2({ quiet: true });
    await loadQueues({ quiet: true });
    await loadAnalytics({ quiet: true });
    await loadPipelines({ quiet: true });
    await loadWorkflows({ quiet: true });
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
$("#refresh").addEventListener("click", async () => {
  await loadOverview();
  await loadR2({ quiet: true });
  await loadQueues({ quiet: true });
  await loadAnalytics({ quiet: true });
  await loadPipelines({ quiet: true });
  await loadWorkflows({ quiet: true });
});
$("#deploy-form").addEventListener("submit", deployWorker);
$("#deploy-file-picker").addEventListener("click", () => $("#deploy-files").click());
$("#deploy-files").addEventListener("change", updateDeployFileStatus);
$("#source-form").addEventListener("submit", connectSource);
$("#source-worker").addEventListener("input", updateDefaultDomainPreview);
$("#kv-search-form").addEventListener("submit", (event) => { event.preventDefault(); loadKeys(); });
$("#kv-editor-form").addEventListener("submit", saveKey);
$("#kv-new").addEventListener("click", clearKey);
$("#kv-delete").addEventListener("click", removeKey);
$("#d1-create-form").addEventListener("submit", createDatabase);
$("#d1-exec-form").addEventListener("submit", executeSql);
$("#r2-bucket-form").addEventListener("submit", saveR2Bucket);
$("#r2-bucket-name").addEventListener("input", updateR2DefaultDomainPreview);
$("#r2-storage-backend").addEventListener("change", toggleR2StorageFields);
$("#r2-object-search").addEventListener("submit", (event) => { event.preventDefault(); loadR2Objects(); });
$("#r2-upload-form").addEventListener("submit", uploadR2Object);
$("#r2-load-more").addEventListener("click", () => loadR2Objects({ append: true }));
$("#r2-delete-bucket").addEventListener("click", deleteR2Bucket);
$("#queue-form").addEventListener("submit", saveQueue);
$("#queue-send-form").addEventListener("submit", sendQueueMessage);
$("#queue-delete").addEventListener("click", deleteQueue);
$("#queue-refresh-dead").addEventListener("click", loadQueueDeadLetters);
$("#analytics-form").addEventListener("submit", saveAnalytics);
$("#analytics-write-form").addEventListener("submit", writeAnalyticsPoint);
$("#analytics-group-form").addEventListener("submit", (event) => {
  event.preventDefault();
  loadAnalyticsGroups().catch((error) => toast(error.message, true));
});
$("#analytics-refresh").addEventListener("click", () => state.analyticsActive && selectAnalytics(state.analyticsActive));
$("#analytics-delete").addEventListener("click", deleteAnalytics);
$("#pipeline-form").addEventListener("submit", savePipeline);
$("#pipeline-token-form").addEventListener("submit", mintPipelineToken);
$("#pipeline-ingest-form").addEventListener("submit", ingestPipelineEvents);
$("#pipeline-flush").addEventListener("click", flushPipeline);
$("#pipeline-refresh").addEventListener("click", () => state.pipelineActive && selectPipeline(state.pipelineActive));
$("#pipeline-delete").addEventListener("click", deletePipeline);
$("#pipeline-copy-token").addEventListener("click", () => copyText($("#pipeline-new-token").textContent, $("#pipeline-copy-token")));
$("#workflow-form").addEventListener("submit", saveWorkflow);
$("#workflow-trigger-form").addEventListener("submit", triggerWorkflow);
$("#workflow-signal-form").addEventListener("submit", sendWorkflowSignal);
$("#workflow-refresh").addEventListener("click", loadWorkflowInstances);
$("#workflow-delete").addEventListener("click", deleteWorkflow);
$("#r2-object-file").addEventListener("change", () => {
  const file = $("#r2-object-file").files?.[0];
  if (file && !$("#r2-object-key").value) $("#r2-object-key").value = file.name;
});
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
  $("#pipeline-new-token").textContent = "";
  $("#pipeline-token-reveal").classList.add("hidden");
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
$("#r2-bucket-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-r2-bucket]");
  if (button) selectR2Bucket(button.dataset.r2Bucket);
});
$("#r2-object-table").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-r2-action]");
  if (!button) return;
  if (button.dataset.r2Action === "download") downloadR2Object(button.dataset.r2Key);
  if (button.dataset.r2Action === "delete") deleteR2Object(button.dataset.r2Key);
});
$("#queue-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-queue]");
  if (button) selectQueue(button.dataset.queue);
});
$("#queue-dead-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-queue-redrive]");
  if (button) redriveQueueMessage(button.dataset.queueRedrive);
});
$("#analytics-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-analytics]");
  if (button) selectAnalytics(button.dataset.analytics);
});
$("#pipeline-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-pipeline]");
  if (button) selectPipeline(button.dataset.pipeline);
});
$("#pipeline-token-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-pipeline-token-revoke]");
  if (button) revokePipelineToken(button.dataset.pipelineTokenRevoke);
});
$("#workflow-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-workflow]");
  if (button) selectWorkflow(button.dataset.workflow);
});
$("#workflow-instances").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-workflow-instance]");
  if (button) openWorkflowInstance(button.dataset.workflowInstance);
});
$("#workflow-instance-actions").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-workflow-action]");
  if (button) runWorkflowAction(button.dataset.workflowAction);
});

setInterval(() => {
  if (state.session) {
    loadOverview({ quiet: true });
    loadWorkerOps();
    if (state.view === "r2") loadR2({ quiet: true });
    if (state.view === "queues") loadQueues({ quiet: true });
    if (state.view === "analytics") loadAnalytics({ quiet: true }).then(() => {
      if (state.analyticsActive) selectAnalytics(state.analyticsActive);
    });
    if (state.view === "pipelines") loadPipelines({ quiet: true }).then(() => {
      if (state.pipelineActive) selectPipeline(state.pipelineActive);
    });
    if (state.view === "workflows") loadWorkflows({ quiet: true }).then(() => {
      if (state.workflowActive) selectWorkflow(state.workflowActive);
    });
  }
}, 10_000);
boot();
