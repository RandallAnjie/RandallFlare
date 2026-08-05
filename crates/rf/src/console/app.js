const token = document.querySelector('meta[name="rf-console-token"]').content;
const consoleMode = document.querySelector('meta[name="rf-console-mode"]').content;
const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

if (consoleMode === "public") document.body.classList.add("auth-required");

const state = {
  overview: null,
  nodes: [],
  nodeActive: null,
  nodePolicyDirty: false,
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
  workerFile: null,
  cronRuns: [],
  cronDlq: [],
  requestLogs: null,
  previews: [],
  projectTab: "overview",
  r2Buckets: [],
  r2Active: null,
  r2Cursor: null,
  r2Objects: [],
  storage: null,
  storageProbes: [],
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
  flows: [],
  flowActive: null,
  flowGraph: { nodes: [], edges: [] },
  flowNodeActive: null,
  flowRuns: [],
  flowRunActive: null,
  networkRules: [],
  networkRuleActive: null,
  networkDevices: [],
  networkDeviceActive: null,
  networkExits: [],
  emailDomains: [],
  emailActive: null,
  emailRoutes: [],
  emailMessages: [],
  emailMessageActive: null,
  emailContext: { buckets: [], workers: [], email_node: null },
  binaries: [],
  binaryActive: null,
  binaryContext: { capabilities: {}, current_os_arch: "linux/amd64" },
  security: null,
  securityDirty: false,
  s3Editing: null,
  auditRecords: [],
};

const titles = {
  overview: ["集群控制", "概览"],
  nodes: ["集群控制", "节点与调度"],
  workers: ["签名清单", "Worker"],
  "worker-new": ["Worker 项目", "新建项目"],
  "worker-detail": ["Worker 项目", "项目详情"],
  kv: ["分布式数据", "KV 存储"],
  r2: ["对象存储", "R2 bucket"],
  storage: ["对象存储", "存储策略"],
  d1: ["分布式 SQLite", "D1 数据库"],
  queues: ["事件驱动", "队列"],
  analytics: ["可观测数据", "Analytics Engine"],
  pipelines: ["数据传输", "Pipeline"],
  workflows: ["耐久执行", "Workflow"],
  flows: ["可视化编排", "Flow"],
  network: ["终端网络", "设备与出口"],
  email: ["去中心化邮件", "邮件路由"],
  binaries: ["安全原生程序", "Binary Deliver"],
  security: ["安全边界", "安全与访问"],
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
  const flows = Array.isArray(data.flows) ? data.flows : [];
  const emailDomains = Array.isArray(data.email_domains) ? data.email_domains : [];
  const binaries = Array.isArray(data.binaries) ? data.binaries : [];
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
  $("#metric-flows").textContent = String(flows.length);
  $("#flow-nav-count").textContent = String(flows.length);
  $("#metric-email").textContent = String(emailDomains.length);
  $("#email-nav-count").textContent = String(emailDomains.length);
  $("#metric-binaries").textContent = String(binaries.length);
  $("#binary-nav-count").textContent = String(binaries.length);
  $("#metric-r2-backend").textContent = data.storage?.policy?.new_bucket_backend === "rclone_sharded"
    ? `${data.storage.policy.shard_remotes?.length || 0} 个签名 rclone 分片盘`
    : data.storage?.rclone ? "本地副本与 rclone 已就绪" : "集群本地多数派副本";
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
  if (String(trigger || "").startsWith("github-pr:")) return "GitHub Pull Request 预览";
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
      ? `<button class="primary" data-build-action="approve" data-build="${escapeHtml(job.id)}" data-node="${escapeHtml(job.approve_node || approveNode || "")}">签署${job.preview ? "预览" : "发布"}</button>` : "";
    const preview = Boolean(job.preview);
    const destination = preview ? "预览环境" : "生产环境";
    const resultLink = job.preview_url && job.state === "deployed" ? `<a class="mini-button" href="${escapeHtml(job.preview_url)}" target="_blank" rel="noreferrer">访问预览 ↗</a>` : "";
    return `<article class="build-row ${job.state === "failed" ? "failed" : ""}">
      <span class="pipeline-state ${terminal ? job.state : "active"}"></span>
      <div><strong>${escapeHtml(job.worker)}</strong><small>${escapeHtml(buildTriggerLabel(job.trigger))} · ${escapeHtml(destination)} · <code>${escapeHtml(short)}</code></small></div>
      <div class="build-stage"><span class="badge ${job.state === "deployed" ? "active" : ""}">${escapeHtml(buildStateLabel(job.state))}</span><small>${job.version ? `${preview ? "预览" : "发布"} v${escapeHtml(job.version)}` : "产物尚未就绪"}</small></div>
      <div class="table-actions">${approval}${resultLink}<button class="mini-button" data-build-action="log" data-build="${escapeHtml(job.id)}">查看日志</button></div>
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
  if (tab === "logs") Promise.all([loadRequestLogs(), loadDetailLogs()]);
  if (tab === "deployments") loadDetailHistory();
  if (tab === "previews") loadWorkerPreviews();
  if (tab === "triggers" && state.activeWorker) loadCronRuns();
  if (tab === "code" && state.workerDetail && !state.workerFile) {
    const worker = state.workerDetail.worker;
    const first = worker.main || worker.modules?.[0]?.path || worker.assets?.[0]?.path;
    if (first) openWorkerFile(first);
  }
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

function renderWorkerSecrets(names = []) {
  const values = [...names].sort();
  const list = $("#project-secret-list");
  list.classList.toggle("empty-state", values.length === 0);
  list.innerHTML = values.length
    ? values.map((name) => `<div class="secret-row"><div><strong>${escapeHtml(name)}</strong><small>已加密 · 值不可回读</small></div><button class="mini-button danger" type="button" data-delete-secret="${escapeHtml(name)}">删除</button></div>`).join("")
    : "尚未配置 Secret。";
  const secure = consoleMode === "local" || Boolean(state.session?.secure_transport);
  $("#project-secret-transport").textContent = secure
    ? "当前连接允许安全写入；后台和 API 始终只返回变量名。"
    : "当前是非加密公共连接，已禁用 Secret 写入。请先启用 HTTPS。";
  $("#project-secret-form button[type=submit]").disabled = Boolean(state.session?.read_only) || !secure;
  $("#project-secret-name").disabled = !secure;
  $("#project-secret-value").disabled = !secure;
}

function workerFileRows(worker) {
  return [
    ...(worker.modules || []).map((file) => ({ ...file, file_type: "module" })),
    ...(worker.assets || []).map((file) => ({ ...file, file_type: "asset" })),
  ].sort((left, right) => left.path.localeCompare(right.path));
}

function workerFilePath(worker, path) {
  return `/api/workers/${encodeURIComponent(worker)}/files/${path.split("/").map(encodeURIComponent).join("/")}`;
}

function renderProjectFiles(worker, source) {
  const files = workerFileRows(worker);
  const list = $("#project-file-list");
  list.classList.toggle("empty-state", files.length === 0);
  list.innerHTML = files.length ? files.map((file) => {
    const active = state.workerFile?.path === file.path;
    const entry = worker.main === file.path;
    return `<button class="code-file-button ${active ? "active" : ""}" type="button" data-worker-file="${escapeHtml(file.path)}"><span>${file.file_type === "module" ? "◇" : "□"}</span><code>${escapeHtml(file.path)}</code><small>${entry ? "入口" : formatBytes(file.size)}</small></button>`;
  }).join("") : "当前版本没有文件。";
  $("#project-code-source-warning").textContent = source
    ? "此项目已连接 GitHub。在线修改会成为一个独立签名版本；下一次 Git 构建可能覆盖它。"
    : "直接编辑会创建新的签名版本，内容块随后由节点间自动分发。";
}

async function openWorkerFile(path) {
  const worker = state.activeWorker;
  if (!worker) return;
  try {
    const data = await api(workerFilePath(worker, path));
    if (state.activeWorker !== worker) return;
    state.workerFile = data;
    renderProjectFiles(state.workerDetail.worker, state.workerDetail.source);
    $("#project-file-form").classList.remove("hidden");
    $("#project-file-empty").classList.add("hidden");
    $("#project-file-title").textContent = data.path;
    $("#project-file-meta").textContent = `${data.file_type === "module" ? data.module_kind || "Worker 模块" : "静态资源"} · ${formatBytes(data.size)} · ${shortId(data.sha256, 18)}`;
    $("#project-file-state").textContent = data.editable ? (data.text == null ? "二进制" : "可编辑") : "超出在线编辑上限";
    $("#project-file-path").value = data.path;
    $("#project-file-type").value = data.file_type;
    $("#project-file-main").checked = state.workerDetail.worker.main === data.path;
    $("#project-file-main").disabled = data.file_type !== "module";
    $("#project-file-content").value = data.text ?? "";
    $("#project-file-content").disabled = data.text == null;
    $("#project-file-binary-note").textContent = data.editable
      ? data.text == null ? "这是二进制文件；可选择本地文件完整替换，路径重命名仍可直接发布。" : "文本按 UTF-8 保存；可使用下方文件选择器完整替换。"
      : data.reason || "此文件不能在浏览器中读取。";
    $("#project-file-upload").value = "";
    $("#project-file-delete").classList.remove("hidden");
  } catch (error) {
    toast(error.message, true);
  }
}

function newWorkerFile() {
  state.workerFile = { path: "", file_type: "module", text: "", content_base64: "", editable: true, is_new: true };
  renderProjectFiles(state.workerDetail?.worker || {}, state.workerDetail?.source);
  $("#project-file-form").classList.remove("hidden");
  $("#project-file-empty").classList.add("hidden");
  $("#project-file-title").textContent = "新建文件";
  $("#project-file-meta").textContent = "选择模块或静态资源；可以使用斜杠创建目录层级。";
  $("#project-file-state").textContent = "尚未发布";
  $("#project-file-path").value = "src/new-file.js";
  $("#project-file-type").value = "module";
  $("#project-file-main").checked = !(state.workerDetail?.worker?.main);
  $("#project-file-main").disabled = false;
  $("#project-file-content").disabled = false;
  $("#project-file-content").value = "export default {\n  async fetch(request, env, ctx) {\n    return new Response(\"Hello from RandallFlare\");\n  }\n};\n";
  $("#project-file-binary-note").textContent = "新文件将随下一份签名清单发布。";
  $("#project-file-upload").value = "";
  $("#project-file-delete").classList.add("hidden");
  $("#project-file-path").focus();
}

async function saveWorkerFile(event) {
  event.preventDefault();
  const worker = state.activeWorker;
  const current = state.workerFile;
  if (!worker || !current) return;
  const path = $("#project-file-path").value.trim();
  const upload = $("#project-file-upload").files?.[0];
  const changes = [];
  if (!current.is_new && current.path !== path) {
    changes.push({ operation: "rename", from: current.path, to: path });
  }
  let contentBase64 = null;
  if (upload) {
    if (upload.size > 25 * 1024 * 1024) {
      toast("单个编辑文件不能超过 25 MiB", true);
      return;
    }
    contentBase64 = bytesToBase64(new Uint8Array(await upload.arrayBuffer()));
  } else if (!$("#project-file-content").disabled) {
    contentBase64 = bytesToBase64(new TextEncoder().encode($("#project-file-content").value));
  } else if (current.content_base64 && (current.path !== path || current.file_type !== $("#project-file-type").value)) {
    contentBase64 = current.content_base64;
  }
  if (current.is_new && contentBase64 == null) contentBase64 = "";
  const fileType = $("#project-file-type").value;
  if (!current.is_new && fileType !== current.file_type && contentBase64 == null) {
    toast("切换大文件类型时必须选择本地文件重新上传", true);
    return;
  }
  if (contentBase64 != null && (current.is_new || contentBase64 !== current.content_base64 || fileType !== current.file_type)) {
    changes.push({ operation: "put", path, content_base64: contentBase64, file_type: fileType });
  }
  const payload = { changes };
  const wasMain = state.workerDetail.worker.main === current.path;
  const wantsMain = $("#project-file-main").checked;
  if (wantsMain && !wasMain) payload.main = path;
  else if (!wantsMain && wasMain) payload.main = "";
  if (!payload.changes.length && payload.main === undefined) {
    toast("文件没有变化", true);
    return;
  }
  try {
    const result = await api(`/api/workers/${encodeURIComponent(worker)}/files`, { method: "POST", body: JSON.stringify(payload) });
    const complete = async () => { state.workerFile = null; await loadOverview({ quiet: true }); await openWorkerDetail(worker, "code"); };
    if (result.pending_approval) showApproval(result, `发布 ${worker} 的文件修改。`, complete);
    else { toast(`${path} 已发布到 ${worker} v${result.version}`); await complete(); }
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteWorkerFile() {
  const worker = state.activeWorker;
  const current = state.workerFile;
  if (!worker || !current?.path || !window.confirm(`要从新版本中删除“${current.path}”吗？旧版本仍可回滚。`)) return;
  try {
    const result = await api(`/api/workers/${encodeURIComponent(worker)}/files`, {
      method: "POST", body: JSON.stringify({ changes: [{ operation: "delete", path: current.path }] }),
    });
    const complete = async () => { state.workerFile = null; await loadOverview({ quiet: true }); await openWorkerDetail(worker, "code"); };
    if (result.pending_approval) showApproval(result, `删除 ${worker} 的文件 ${current.path}。`, complete);
    else { toast(`${current.path} 已从新版本删除`); await complete(); }
  } catch (error) {
    toast(error.message, true);
  }
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
  state.workerFile = state.workerFile && workerFileRows(worker).some((file) => file.path === state.workerFile.path) ? state.workerFile : null;

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
    <div><dt>Email 绑定</dt><dd>${escapeHtml(Object.keys(worker.email_bindings || {}).length)} 项</dd></div>
    <div><dt>Service 绑定</dt><dd>${escapeHtml(Object.keys(worker.service_bindings || {}).length)} 项</dd></div>
    <div><dt>加密 Secret</dt><dd>${escapeHtml(worker.secret_names?.length || 0)} 项</dd></div>
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
  $("#project-email-bindings").value = mapToLines(worker.email_bindings);
  $("#project-service-bindings").value = mapToLines(worker.service_bindings);
  $("#project-binary-bindings").value = mapToLines(worker.binary_bindings);
  renderWorkerSecrets(worker.secret_names || []);
  $("#project-crons").value = (worker.crons || []).join("\n");
  $("#project-cron-fire-expression").innerHTML = ["manual", ...(worker.crons || [])]
    .map((expression) => `<option value="${escapeHtml(expression)}">${escapeHtml(expression === "manual" ? "manual（手动）" : expression)}</option>`)
    .join("");
  $("#project-compatibility-date").value = worker.compatibility_date;
  $("#project-compatibility-flags").value = (worker.compatibility_flags || []).join("\n");
  $("#project-required-tags").value = (worker.required_tags || []).join("\n");
  $("#project-source-repository").value = source?.repository?.replace(/\.git$/, "") || "";
  $("#project-source-branch").value = source?.branch || "main";
  $("#project-source-root").value = source?.root || ".";
  $("#project-source-command").value = source?.build_command || "";
  $("#project-source-output").value = source?.output_dir || ".";
  $("#project-source-private").checked = Boolean(source?.use_github_token);
  $("#project-source-webhook").checked = source ? Boolean(source.webhook) : true;
  $("#project-source-pr-previews").checked = source ? Boolean(source.preview_pull_requests) : true;
  $("#project-source-pr-previews").disabled = !$("#project-source-webhook").checked;
  $("#project-source-panel .settings-copy .muted").textContent = source
    ? "编辑仓库、分支与构建命令。源码配置也由管理员签名并在集群内复制。"
    : "该项目尚未连接 GitHub；填写配置即可接入构建与推送部署。";
  $("#project-source-form button[type=submit]").textContent = source ? "保存 Git 配置" : "连接 GitHub 仓库";
  $("#project-source-disconnect").classList.toggle("hidden", !source);
  $("#project-source-status").innerHTML = source ? `
    <div class="source-connection"><span class="dot online"></span><p><strong>已连接</strong><small>代码源 v${escapeHtml(source.version)} · ${source.webhook ? "自动构建已启用" : "仅手动构建"}${source.preview_pull_requests ? " · PR 预览已启用" : ""}</small></p></div>
    ${source.webhook ? `<div class="webhook-grid"><span>回调地址</span><code>${escapeHtml(`${location.origin}${source.webhook_path}`)}</code><span>密钥</span><code>${escapeHtml(source.webhook_secret || "不可用")}</code><span>事件</span><code>${source.preview_pull_requests ? "推送与 Pull Request" : "仅推送"}</code></div>` : ""}` : '<div class="source-connection"><span class="dot pending"></span><p><strong>尚未连接</strong><small>填写右侧表单即可启用 GitHub 构建。</small></p></div>';
  $("#project-identifiers").innerHTML = `
    <div><dt>Worker 名称</dt><dd class="mono">${escapeHtml(worker.name)}</dd></div>
    <div><dt>当前版本</dt><dd class="mono">v${escapeHtml(worker.version)}</dd></div>
    <div><dt>清单摘要</dt><dd class="mono">${escapeHtml(worker.digest)}</dd></div>
    <div><dt>入口模块</dt><dd class="mono">${escapeHtml(worker.main || "静态资源项目")}</dd></div>`;
  $("#detail-builds").innerHTML = buildRowsHtml(state.builds.filter((job) => job.worker === worker.name));
  renderProjectFiles(worker, source);
  if (state.projectTab === "code" && !state.workerFile) {
    const first = worker.main || worker.modules?.[0]?.path || worker.assets?.[0]?.path;
    if (first) openWorkerFile(first);
  }
}

async function openWorkerDetail(name, tab = "overview") {
  if (state.activeWorker !== name) state.workerFile = null;
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
    await Promise.all([loadDetailHistory(), tab === "logs" ? Promise.all([loadRequestLogs(), loadDetailLogs()]) : Promise.resolve()]);
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

function previewSourceLabel(source) {
  if (source?.type === "pull_request") return `Pull Request #${source.number} · ${source.branch}`;
  if (source?.type === "commit") return `提交 ${String(source.commit || "").slice(0, 12)}`;
  return `历史版本 v${source?.version ?? "—"}`;
}

function renderWorkerPreviews(data) {
  state.previews = data.previews || [];
  const select = $("#project-preview-version");
  const selected = select.value;
  select.innerHTML = (data.versions || []).slice().reverse().map((version) => `<option value="${escapeHtml(version)}">v${escapeHtml(version)}</option>`).join("");
  if ([...select.options].some((option) => option.value === selected)) select.value = selected;
  $("#project-preview-ttl").max = data.max_ttl_days || 90;
  if (!$("#project-preview-ttl").value) $("#project-preview-ttl").value = data.default_ttl_days || 30;
  $("#project-preview-list").innerHTML = state.previews.length ? state.previews.map((preview) => {
    const active = Boolean(preview.active);
    const expires = new Date(preview.expires_at_ms).toLocaleString("zh-CN");
    return `<article class="build-row ${active ? "" : "failed"}">
      <span class="pipeline-state ${active ? "deployed" : "failed"}"></span>
      <div><strong>${escapeHtml(preview.alias)}</strong><small>${escapeHtml(previewSourceLabel(preview.source))} · ${active ? `到期于 ${expires}` : `已于 ${expires} 到期`}</small><code>${escapeHtml(preview.hostname)}</code></div>
      <div class="build-stage"><span class="badge ${active ? "active" : ""}">${active ? (preview.running_on_this_node ? "本节点运行中" : "正在分发") : "已到期"}</span><small>清单 v${escapeHtml(preview.manifest_version)} · 资源 v${escapeHtml(preview.resource_version)}</small></div>
      <div class="table-actions">${active ? `<a class="mini-button" href="${escapeHtml(preview.url)}" target="_blank" rel="noreferrer">访问 ↗</a>` : ""}<button class="mini-button danger" type="button" data-preview-delete="${escapeHtml(preview.alias)}">删除</button></div>
    </article>`;
  }).join("") : '<div class="empty-state">尚无预览。可以选择历史版本创建，也可以在代码源中启用 Pull Request 预览。</div>';
}

async function loadWorkerPreviews({ quiet = true } = {}) {
  const worker = state.activeWorker;
  if (!worker) return;
  try {
    const data = await api(`/api/workers/${encodeURIComponent(worker)}/previews`);
    if (state.activeWorker === worker) renderWorkerPreviews(data);
  } catch (error) {
    $("#project-preview-list").innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
    if (!quiet) toast(error.message, true);
  }
}

async function createWorkerPreview(event) {
  event.preventDefault();
  const worker = state.activeWorker;
  if (!worker) return;
  const version = Number($("#project-preview-version").value);
  const ttlDays = Number($("#project-preview-ttl").value);
  try {
    const result = await api(`/api/workers/${encodeURIComponent(worker)}/previews`, {
      method: "POST",
      body: JSON.stringify({ version, ttl_days: ttlDays }),
    });
    showApproval(result, `发布 ${worker} v${version} 的隔离预览。`, () => loadWorkerPreviews({ quiet: false }));
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteWorkerPreview(alias) {
  const worker = state.activeWorker;
  if (!worker || !window.confirm(`要停止并删除预览“${alias}”吗？`)) return;
  try {
    const result = await api(`/api/workers/${encodeURIComponent(worker)}/previews/${encodeURIComponent(alias)}`, { method: "DELETE" });
    showApproval(result, `停止 ${worker} 的预览 ${alias}。`, () => loadWorkerPreviews({ quiet: false }));
  } catch (error) {
    toast(error.message, true);
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
    const unavailable = data.unavailable_nodes?.length || 0;
    $("#detail-log-meta").textContent = `${data.nodes?.length || 0} 个节点可用${unavailable ? ` · ${unavailable} 个节点暂不可用` : ""} · 最近 ${data.lines?.length || 0} 条`;
    $("#detail-logs").textContent = (data.lines || []).map((line) => `${new Date(line.at_ms).toLocaleString("zh-CN")} [${line.node_label || shortId(line.node, 10)}] [v${line.version}] [${streams[line.stream] || line.stream}] ${line.message}`).join("\n") || "所有存活节点均尚未记录运行输出。";
  } catch (error) {
    $("#detail-logs").textContent = error.message;
  }
}

function renderRequestTrend(hours = []) {
  const totals = hours.map((hour) => (hour.status_2xx || 0) + (hour.status_3xx || 0) + (hour.status_4xx || 0) + (hour.status_5xx || 0) + (hour.other || 0));
  const maximum = Math.max(1, ...totals);
  const chart = hours.map((hour, index) => {
    const when = new Date(hour.start_ms);
    const total = totals[index];
    const title = `${when.toLocaleString("zh-CN", { month: "2-digit", day: "2-digit", hour: "2-digit" })}：${total} 次（2xx ${hour.status_2xx || 0}，3xx ${hour.status_3xx || 0}，4xx ${hour.status_4xx || 0}，5xx ${hour.status_5xx || 0}）`;
    // Height classes keep the chart compatible with the console's strict
    // style-src CSP; inline styles are intentionally forbidden.
    const height = (value) => `h${Math.round(Math.max(0, Number(value || 0)) / maximum * 10)}`;
    const label = index % 6 === 0 || index === hours.length - 1 ? `${String(when.getHours()).padStart(2, "0")}:00` : "";
    return `<div class="request-hour" title="${escapeHtml(title)}"><div class="request-hour-stack"><span class="s2 ${height(hour.status_2xx)}"></span><span class="s3 ${height(hour.status_3xx)}"></span><span class="s4 ${height(hour.status_4xx)}"></span><span class="s5 ${height(hour.status_5xx)}"></span><span class="so ${height(hour.other)}"></span></div><small>${label}</small></div>`;
  }).join("");
  $("#request-log-trend").innerHTML = `<div class="request-trend-grid">${chart || '<div class="empty-state">暂无趋势数据。</div>'}</div>`;
  $("#request-log-trend").setAttribute("aria-label", `最近 24 小时共 ${totals.reduce((sum, value) => sum + value, 0)} 次请求`);
}

async function loadRequestLogs() {
  const name = state.activeWorker;
  if (!name) return;
  const selectedHostname = $("#request-log-hostname")?.value || "";
  const selectedStatus = $("#request-log-status")?.value || "";
  $("#request-log-rows").innerHTML = '<tr><td colspan="7" class="empty-cell">正在聚合各节点请求日志…</td></tr>';
  try {
    const params = new URLSearchParams({ limit: "300" });
    if (selectedHostname) params.set("hostname", selectedHostname);
    if (selectedStatus) params.set("status", selectedStatus);
    const data = await api(`/api/workers/${encodeURIComponent(name)}/request-log?${params}`);
    if (state.activeWorker !== name) return;
    state.requestLogs = data;
    const hostnames = [...new Set([...(data.hostnames || []), selectedHostname].filter(Boolean))].sort();
    $("#request-log-hostname").innerHTML = `<option value="">全部域名</option>${hostnames.map((hostname) => `<option value="${escapeHtml(hostname)}"${hostname === selectedHostname ? " selected" : ""}>${escapeHtml(hostname)}</option>`).join("")}`;
    const unavailable = data.unavailable_nodes?.length || 0;
    const count24h = (data.hours || []).reduce((sum, hour) => sum + (hour.status_2xx || 0) + (hour.status_3xx || 0) + (hour.status_4xx || 0) + (hour.status_5xx || 0) + (hour.other || 0), 0);
    $("#request-log-meta").textContent = `${data.nodes?.length || 0} 个节点可用${unavailable ? ` · ${unavailable} 个节点暂不可用` : ""} · 24 小时 ${count24h} 次请求 · 当前显示 ${data.entries?.length || 0} 条`;
    renderRequestTrend(data.hours || []);
    const labels = new Map((data.nodes || []).map((node) => [node.id, node.label || shortId(node.id, 10)]));
    $("#request-log-rows").innerHTML = (data.entries || []).map((entry) => {
      const statusClass = `s${Math.floor(Number(entry.status_code) / 100)}`;
      return `<tr><td>${escapeHtml(new Date(entry.called_at_ms).toLocaleString("zh-CN"))}</td><td title="${escapeHtml(entry.node)}">${escapeHtml(labels.get(entry.node) || shortId(entry.node, 10))}</td><td><div class="request-path" title="${escapeHtml(entry.path)}"><span class="request-method">${escapeHtml(entry.method)}</span>${escapeHtml(entry.path)}</div></td><td>${escapeHtml(entry.hostname)}</td><td><span class="request-status ${statusClass}">${escapeHtml(entry.status_code)}</span></td><td>${escapeHtml(entry.duration_ms)} ms</td><td>v${escapeHtml(entry.version)}</td></tr>`;
    }).join("") || '<tr><td colspan="7" class="empty-cell">当前筛选条件下尚无请求记录。</td></tr>';
  } catch (error) {
    $("#request-log-meta").textContent = error.message;
    $("#request-log-trend").innerHTML = "";
    $("#request-log-rows").innerHTML = `<tr><td colspan="7" class="empty-cell">${escapeHtml(error.message)}</td></tr>`;
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
      email_bindings: linesToMap($("#project-email-bindings").value, "Email 绑定"),
      service_bindings: linesToMap($("#project-service-bindings").value, "Service 绑定"),
      binary_bindings: linesToMap($("#project-binary-bindings").value, "Binary Deliver 绑定"),
    };
    await updateWorkerSettings(payload, `更新 ${state.activeWorker} 的变量与绑定。`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function saveWorkerSecret(event) {
  event.preventDefault();
  const worker = state.activeWorker;
  const binding = $("#project-secret-name").value.trim();
  const valueInput = $("#project-secret-value");
  if (!worker || !binding || !valueInput.value) return;
  if (consoleMode === "public" && !state.session?.secure_transport) {
    toast("必须先通过 HTTPS 打开管理后台，才能写入 Secret", true);
    return;
  }
  try {
    const result = await api(`/api/workers/${encodeURIComponent(worker)}/secrets/${encodeURIComponent(binding)}`, {
      method: "PUT",
      body: JSON.stringify({ value: valueInput.value }),
    });
    valueInput.value = "";
    $("#project-secret-name").value = "";
    if (result.pending_approval) {
      showApproval(result, `写入 ${worker} 的加密 Secret ${binding}。`);
    } else {
      toast(`${binding} 已加密写入 ${worker}`);
      await loadOverview({ quiet: true });
      await openWorkerDetail(worker, state.projectTab);
    }
  } catch (error) {
    valueInput.value = "";
    toast(error.message, true);
  }
}

async function deleteWorkerSecret(binding) {
  const worker = state.activeWorker;
  if (!worker || !window.confirm(`要从 ${worker} 删除 Secret“${binding}”吗？依赖它的请求可能立即失败。`)) return;
  try {
    const result = await api(`/api/workers/${encodeURIComponent(worker)}/secrets/${encodeURIComponent(binding)}`, { method: "DELETE" });
    if (result.pending_approval) {
      showApproval(result, `删除 ${worker} 的加密 Secret ${binding}。`);
    } else {
      toast(`${binding} 已从 ${worker} 删除`);
      await loadOverview({ quiet: true });
      await openWorkerDetail(worker, state.projectTab);
    }
  } catch (error) {
    toast(error.message, true);
  }
}

async function saveProjectTriggers(event) {
  event.preventDefault();
  const crons = $("#project-crons").value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean);
  await updateWorkerSettings({ crons }, `更新 ${state.activeWorker} 的定时触发器。`);
}

function renderCronRuns() {
  const recent = $("#project-cron-runs");
  recent.classList.toggle("empty-state", state.cronRuns.length === 0);
  recent.innerHTML = state.cronRuns.length
    ? state.cronRuns.map((run) => {
      const success = run.status === "success";
      return `<article class="build-row ${success ? "success" : "failed"}"><span class="pipeline-state ${success ? "success" : "failed"}"></span><div><strong>${escapeHtml(run.expression)}</strong><small>${escapeHtml(new Date(run.started_at_ms).toLocaleString("zh-CN"))} · 第 ${escapeHtml(run.attempt)} 次尝试 · 节点 ${escapeHtml(shortId(run.node, 14))}</small><code>${escapeHtml(run.id)}</code></div><div><span class="badge">${success ? "成功" : "失败"}${run.status_code ? ` · ${escapeHtml(run.status_code)}` : ""}</span><small>${escapeHtml(run.error_brief || (run.replay_of ? `重放自 ${run.replay_of}` : ""))}</small></div></article>`;
    }).join("")
    : "尚无 Cron 执行记录。";
  const dlq = $("#project-cron-dlq");
  $("#project-cron-dlq-count").textContent = `${state.cronDlq.length} 条`;
  dlq.classList.toggle("empty-state", state.cronDlq.length === 0);
  dlq.innerHTML = state.cronDlq.length
    ? state.cronDlq.map((run) => `<article class="build-row failed"><span class="pipeline-state failed"></span><div><strong>${escapeHtml(run.expression)}</strong><small>${escapeHtml(new Date(run.scheduled_at_ms).toLocaleString("zh-CN"))} · 第 ${escapeHtml(run.attempt)} 次尝试${run.replayed_at_ms ? ` · 最近重放 ${escapeHtml(new Date(run.replayed_at_ms).toLocaleString("zh-CN"))}` : ""}</small><code>${escapeHtml(run.error_brief || run.id)}</code></div><div class="table-actions"><button class="mini-button" type="button" data-cron-replay="${escapeHtml(run.id)}">重放</button><button class="mini-button danger" type="button" data-cron-delete="${escapeHtml(run.id)}">删除</button></div></article>`).join("")
    : "Cron DLQ 为空。";
}

async function loadCronRuns({ quiet = false } = {}) {
  const worker = state.activeWorker;
  if (!worker) return;
  try {
    const [recent, dlq] = await Promise.all([
      api(`/api/workers/${encodeURIComponent(worker)}/cron-runs?limit=100`),
      api(`/api/workers/${encodeURIComponent(worker)}/cron-runs?dlq=true&limit=100`),
    ]);
    if (state.activeWorker !== worker) return;
    state.cronRuns = recent.runs || [];
    state.cronDlq = dlq.runs || [];
    renderCronRuns();
  } catch (error) {
    if (!quiet) toast(error.message, true);
  }
}

async function fireProjectCron(event) {
  event.preventDefault();
  const worker = state.activeWorker;
  if (!worker) return;
  const expression = $("#project-cron-fire-expression").value;
  try {
    const result = await api(`/api/workers/${encodeURIComponent(worker)}/cron-fire`, {
      method: "POST",
      body: JSON.stringify({ expression }),
    });
    const run = result.run;
    toast(`Cron ${expression} 已执行：${run.status === "success" ? "成功" : "失败"}${run.status_code ? `（HTTP ${run.status_code}）` : ""}`, run.status !== "success");
    await Promise.all([loadCronRuns({ quiet: true }), loadDetailLogs()]);
  } catch (error) {
    toast(error.message, true);
  }
}

async function replayProjectCron(id) {
  const worker = state.activeWorker;
  if (!worker || !window.confirm("要立即重放这条 Cron 死信吗？本次只执行一次。")) return;
  try {
    const result = await api(`/api/workers/${encodeURIComponent(worker)}/cron-runs/${encodeURIComponent(id)}/replay`, { method: "POST", body: "{}" });
    toast(`Cron 重放完成：${result.run.status === "success" ? "成功" : "失败"}`, result.run.status !== "success");
    await Promise.all([loadCronRuns({ quiet: true }), loadDetailLogs()]);
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteProjectCronDlq(id) {
  const worker = state.activeWorker;
  if (!worker || !window.confirm("要永久删除这条 Cron DLQ 记录吗？")) return;
  try {
    await api(`/api/workers/${encodeURIComponent(worker)}/cron-runs/${encodeURIComponent(id)}`, { method: "DELETE" });
    toast("Cron DLQ 记录已删除");
    await loadCronRuns({ quiet: true });
  } catch (error) {
    toast(error.message, true);
  }
}

async function saveProjectSettings(event) {
  event.preventDefault();
  await updateWorkerSettings(
    {
      compatibility_date: $("#project-compatibility-date").value,
      compatibility_flags: $("#project-compatibility-flags").value.split(/\s+/).map((value) => value.trim()).filter(Boolean),
      required_tags: $("#project-required-tags").value.split(/\s+/).map((value) => value.trim()).filter(Boolean),
    },
    `更新 ${state.activeWorker} 的兼容日期与标志。`,
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
    preview_pull_requests: $("#project-source-webhook").checked && $("#project-source-pr-previews").checked,
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
    preview_pull_requests: $("#source-webhook").checked && $("#source-pr-previews").checked,
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
  $("#source-pr-previews").checked = Boolean(source.preview_pull_requests);
  $("#source-pr-previews").disabled = !source.webhook;
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
  }, job.preview ? `发布 ${job.worker} 构建的隔离预览。` : `部署为 ${job.worker} 构建的不可变产物。`, async () => {
    await loadWorkerOps();
    if (job.preview && state.activeWorker === job.worker) await loadWorkerPreviews();
  });
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
      const backend = bucket.spec?.storage_policy
        ? "签名 rclone 分片"
        : storage.type === "rclone"
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
    const policyReady = (data.storage_policy?.shard_remotes || []).length > 0;
    $("#r2-storage-backend").querySelector('option[value="policy"]').disabled = !policyReady;
    if (!state.r2Active && data.storage_policy?.new_bucket_backend === "rclone_sharded" && policyReady) {
      $("#r2-storage-backend").value = "policy";
      toggleR2StorageFields();
    }
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
  $("#r2-storage-backend").value = spec.storage_policy ? "policy" : storage.type || "local";
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
  const storageSummary = bucket.spec?.storage_policy
    ? `签名 rclone 分片策略 ${bucket.spec.storage_policy} · 配置 v${bucket.version}`
    : storage.type === "rclone"
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

function storageLocationCopy(storage) {
  if (storage?.type === "rclone_shard") return `分片 · ${storage.remote}:${storage.prefix || "（根）"}`;
  if (storage?.type === "rclone") return `固定 rclone · ${storage.remote}:${storage.prefix || "（根）"}`;
  return "集群本地副本";
}

function renderStorage() {
  const data = state.storage;
  if (!data) return;
  const policy = data.policy || {};
  const distribution = data.distribution || [];
  const objects = distribution.reduce((total, item) => total + Number(item.objects || 0), 0);
  const bytes = distribution.reduce((total, item) => total + Number(item.bytes || 0), 0);
  $("#storage-version").textContent = data.version ? `v${data.version}` : "内置";
  $("#storage-digest").textContent = data.digest ? shortId(data.digest, 18) : "安全本地默认值";
  $("#storage-remote-count").textContent = String((policy.shard_remotes || []).length);
  $("#storage-nav-count").textContent = String((policy.shard_remotes || []).length);
  $("#storage-object-count").textContent = String(objects);
  $("#storage-byte-count").textContent = formatBytes(bytes);
  $("#storage-default-backend").textContent = policy.new_bucket_backend === "rclone_sharded" ? "rclone 分片" : "本地";
  $("#storage-default").value = policy.new_bucket_backend || "local";
  $("#storage-remotes").value = (policy.shard_remotes || []).join("\n");
  $("#storage-prefix").value = policy.shard_prefix || "";
  const list = $("#storage-distribution");
  list.classList.toggle("empty-state", distribution.length === 0);
  list.innerHTML = distribution.length ? distribution.map((item) => `<div class="database-row"><div><strong>${escapeHtml(storageLocationCopy(item.storage))}</strong><small>${escapeHtml(item.buckets)} 个 bucket · ${escapeHtml(item.objects)} 个对象</small></div><span class="badge">${escapeHtml(formatBytes(item.bytes))}</span></div>`).join("") : "暂无已索引对象。";
}

function renderStorageProbes() {
  const list = $("#storage-probes");
  list.classList.toggle("empty-state", state.storageProbes.length === 0);
  list.innerHTML = state.storageProbes.length ? state.storageProbes.map((node) => {
    const probes = node.probes || [];
    const rows = probes.map((probe) => `<div class="grant-row"><strong>${escapeHtml(probe.remote)}</strong><small>${escapeHtml(probe.reachable ? "可读写" : probe.error || "连接失败")}</small><span class="badge ${probe.reachable ? "active" : "danger"}">${probe.reachable ? "可达" : "不可达"}</span></div>`).join("");
    return `<div class="probe-node"><div class="panel-head"><div><strong>${escapeHtml(node.label)}</strong><small>${escapeHtml(node.api || shortId(node.node))}</small></div><span class="badge ${node.error ? "danger" : ""}">${node.error ? "节点不可达" : `${probes.filter((probe) => probe.reachable).length}/${probes.length}`}</span></div>${node.error ? `<p class="input-note">${escapeHtml(node.error)}</p>` : rows || '<p class="input-note">策略中没有 remote。</p>'}</div>`;
  }).join("") : "策略中没有 remote，或尚未执行探测。";
}

async function loadStorage({ quiet = false } = {}) {
  try {
    state.storage = await api("/api/storage");
    renderStorage();
    if (!quiet) toast("存储策略与对象分布已刷新");
  } catch (error) { if (!quiet) toast(error.message, true); }
}

async function saveStorage(event) {
  event.preventDefault();
  const payload = {
    new_bucket_backend: $("#storage-default").value,
    shard_remotes: $("#storage-remotes").value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean),
    shard_prefix: $("#storage-prefix").value.trim().replace(/^\/+|\/+$/g, ""),
  };
  try {
    const result = await api("/api/storage", { method: "POST", body: JSON.stringify(payload) });
    const complete = async () => { state.storageProbes = []; renderStorageProbes(); await loadStorage({ quiet: true }); await loadR2({ quiet: true }); };
    if (result.pending_approval) showApproval(result, "批准全局存储默认值和有序 rclone 分片集合。", complete);
    else { toast("签名存储策略已保存"); await complete(); }
  } catch (error) { toast(error.message, true); }
}

async function probeStorage() {
  try {
    const data = await api("/api/storage/probe", { method: "POST", body: "{}" });
    state.storageProbes = data.nodes || [];
    renderStorageProbes();
    const failed = state.storageProbes.reduce((total, node) => total + Number(Boolean(node.error)) + (node.probes || []).filter((probe) => !probe.reachable).length, 0);
    toast(failed ? `集群探测发现 ${failed} 项不可达` : "所有节点上的策略 remote 均可达", failed > 0);
  } catch (error) { toast(error.message, true); }
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

const flowNodeLabels = {
  trigger: "触发器", worker: "Worker", http: "HTTP 请求", branch: "条件分支",
  transform: "数据转换", loop: "遍历数组", kv: "KV 存储", d1: "D1 数据库",
  r2: "R2 对象", queue: "队列", analytics: "Analytics", pipeline: "Pipeline",
  workflow: "Workflow", subflow: "子 Flow", email: "邮件",
};

const flowNodeDefaults = {
  trigger: {}, worker: { worker: "", method: "POST", path: "/" },
  http: { url: "https://api.example.com", method: "POST" },
  branch: { condition: "input.ok == true" }, transform: { expression: "input" },
  loop: { items: "input.items" }, kv: { namespace: "", action: "get", key: "{{ input.key }}" },
  d1: { database: "", sql: "SELECT 1", params: [] }, r2: { bucket: "", action: "get", key: "{{ input.key }}" },
  queue: { queue: "", body: "{{ input }}" }, analytics: { dataset: "", points: "{{ input }}" },
  pipeline: { pipeline: "", events: "{{ input }}" }, workflow: { workflow: "", input: "{{ input }}" },
  subflow: { flow: "", input: "{{ input }}" }, email: {},
};

function cloneJson(value) { return JSON.parse(JSON.stringify(value)); }

function emptyFlowGraph() {
  return {
    nodes: [{ id: "start", type: "flowNode", position: { x: 60, y: 90 }, data: { nodeType: "trigger", label: "开始", onError: "stop" } }],
    edges: [],
  };
}

function normalizeFlowGraph(graph) {
  return {
    nodes: Array.isArray(graph?.nodes) ? graph.nodes.map((node) => ({
      id: String(node.id || "node"), type: node.type || "flowNode",
      position: { x: Number(node.position?.x || 0), y: Number(node.position?.y || 0) },
      data: { ...node.data, nodeType: node.data?.nodeType || "transform", label: node.data?.label || "", onError: node.data?.onError || "stop" },
    })) : [],
    edges: Array.isArray(graph?.edges) ? graph.edges.map((edge) => ({ ...edge })) : [],
  };
}

function flowStatusLabel(status) {
  return { queued: "已排队", running: "运行中", complete: "已完成", failed: "失败", cancelled: "已取消", skipped: "已跳过" }[status] || status || "未知";
}

function flowNodeConfig(node) {
  const { nodeType, label, onError, ...config } = node.data || {};
  return config;
}

function updateFlowTriggerFields() {
  const trigger = $("#flow-trigger").value;
  $("#flow-cron").disabled = trigger !== "cron";
  const flow = state.flows.find((item) => item.name === state.flowActive);
  const needsToken = trigger === "webhook" && !(flow?.spec?.tokens || []).length;
  $("#flow-first-token-label").classList.toggle("hidden", !needsToken);
  $("#flow-first-token").required = needsToken;
}

function fillFlowForm(flow) {
  const spec = flow?.spec || {};
  $("#flow-name").value = flow?.name || "";
  $("#flow-description").value = spec.description || "";
  $("#flow-trigger").value = spec.trigger || "manual";
  $("#flow-cron").value = spec.cron || "";
  $("#flow-hostnames").value = (spec.hostnames || []).join("\n");
  $("#flow-retention").value = spec.retention_days || 30;
  $("#flow-concurrency").value = spec.max_concurrent_runs ?? 32;
  $("#flow-alert-env").value = spec.alert_webhook_env || "";
  $("#flow-suspended").checked = Boolean(spec.suspended);
  $("#flow-suspend-reason").value = spec.suspend_reason || "";
  $("#flow-first-token").value = "";
  updateFlowTriggerFields();
}

function renderFlows() {
  $("#flow-count").textContent = `${state.flows.length} 个 Flow`;
  $("#flow-nav-count").textContent = String(state.flows.length);
  const list = $("#flow-list");
  list.classList.toggle("empty-state", state.flows.length === 0);
  list.innerHTML = state.flows.length ? state.flows.map((flow) => {
    const stats = flow.stats || {};
    const active = flow.name === state.flowActive ? " active" : "";
    const copy = flow.spec?.suspended ? "已暂停" : `${Number(stats.queued || 0) + Number(stats.running || 0)} 活跃 · ${stats.failed || 0} 失败`;
    return `<button class="database-item${active}" type="button" data-flow="${escapeHtml(flow.name)}"><span><strong>${escapeHtml(flow.name)}</strong><small>${escapeHtml(flow.spec?.trigger || "manual")} · ${escapeHtml(copy)}</small></span><span>${flow.spec?.suspended ? "已暂停" : "打开 →"}</span></button>`;
  }).join("") : "暂无 Flow。";
}

async function loadFlows({ quiet = false } = {}) {
  try {
    const data = await api("/api/flows");
    state.flows = data.flows || [];
    if (state.flowActive && !state.flows.some((item) => item.name === state.flowActive)) newFlow();
    if (!state.flowActive && state.flowGraph.nodes.length === 0) {
      state.flowGraph = emptyFlowGraph();
      state.flowNodeActive = "start";
      fillFlowForm(null);
      renderFlowCanvas();
    }
    renderFlows();
    if (!quiet) toast("Flow 已刷新");
  } catch (error) { if (!quiet) toast(error.message, true); }
}

function newFlow() {
  state.flowActive = null;
  state.flowRunActive = null;
  state.flowRuns = [];
  state.flowGraph = emptyFlowGraph();
  state.flowNodeActive = "start";
  fillFlowForm(null);
  $("#flow-active-name").textContent = "新建 Flow";
  $("#flow-endpoint").textContent = "保存后会获得确定性的默认入口域名。";
  $("#flow-delete").classList.add("hidden");
  $("#flow-token-form").classList.add("hidden");
  $("#flow-trigger-form").classList.add("hidden");
  $("#flow-run-panel").classList.add("hidden");
  $("#flow-runs").textContent = "暂无运行。";
  $("#flow-runs").classList.add("empty-state");
  renderFlows();
  renderFlowCanvas();
}

async function selectFlow(name) {
  const flow = state.flows.find((item) => item.name === name);
  if (!flow) return;
  state.flowActive = name;
  state.flowRunActive = null;
  state.flowNodeActive = flow.spec?.graph?.nodes?.[0]?.id || null;
  state.flowGraph = normalizeFlowGraph(cloneJson(flow.spec?.graph || emptyFlowGraph()));
  fillFlowForm(flow);
  renderFlows();
  renderFlowCanvas();
  renderFlowTokens(flow);
  $("#flow-active-name").textContent = name;
  const endpoint = flow.hostnames?.[0];
  $("#flow-endpoint").textContent = endpoint ? `入口：https://${endpoint}/ · 定义 v${flow.version}` : `定义 v${flow.version} · 当前节点未配置默认域名`;
  $("#flow-delete").classList.remove("hidden");
  $("#flow-token-form").classList.remove("hidden");
  $("#flow-trigger-form").classList.remove("hidden");
  $("#flow-run-panel").classList.add("hidden");
  const stats = flow.stats || {};
  $("#flow-active-count").textContent = String(Number(stats.queued || 0) + Number(stats.running || 0));
  $("#flow-complete-count").textContent = String(stats.complete || 0);
  $("#flow-failed-count").textContent = String(stats.failed || 0);
  $("#flow-cancelled-count").textContent = String(stats.cancelled || 0);
  await loadFlowRuns();
}

function renderFlowCanvas(syncJson = true) {
  const graph = state.flowGraph;
  const nodes = $("#flow-nodes");
  $("#flow-canvas-empty").classList.toggle("hidden", graph.nodes.length > 0);
  nodes.innerHTML = graph.nodes.map((node) => {
    const selected = node.id === state.flowNodeActive ? " selected" : "";
    const type = node.data.nodeType;
    const icon = (flowNodeLabels[type] || type).slice(0, 2);
    return `<button class="flow-node${selected}" type="button" data-flow-node="${escapeHtml(node.id)}" style="left:${Math.max(0, node.position.x)}px;top:${Math.max(0, node.position.y)}px"><span class="flow-node-icon">${escapeHtml(icon)}</span><span><strong>${escapeHtml(node.data.label || flowNodeLabels[type] || type)}</strong><small>${escapeHtml(type)} · ${escapeHtml(node.id)}</small></span></button>`;
  }).join("");
  renderFlowEdges();
  renderFlowEdgeEditor();
  renderFlowNodeInspector();
  if (syncJson) $("#flow-graph-json").value = JSON.stringify(graph, null, 2);
}

function renderFlowEdges() {
  const graph = state.flowGraph;
  const byId = new Map(graph.nodes.map((node) => [node.id, node]));
  $("#flow-edges").innerHTML = `<defs><marker id="flow-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse"><path class="flow-edge-arrow" d="M 0 0 L 10 5 L 0 10 z"></path></marker></defs>${graph.edges.map((edge) => {
    const source = byId.get(edge.source); const target = byId.get(edge.target);
    if (!source || !target) return "";
    const x1 = source.position.x + 174, y1 = source.position.y + 37, x2 = target.position.x, y2 = target.position.y + 37;
    const bend = Math.max(55, Math.abs(x2 - x1) * .45);
    return `<path class="flow-edge${edge.sourceHandle ? " branch" : ""}" d="M ${x1} ${y1} C ${x1 + bend} ${y1}, ${x2 - bend} ${y2}, ${x2} ${y2}" marker-end="url(#flow-arrow)"></path>`;
  }).join("")}`;
}

function renderFlowNodeInspector() {
  const node = state.flowGraph.nodes.find((node) => node.id === state.flowNodeActive);
  $("#flow-node-form").classList.toggle("hidden", !node);
  $("#flow-node-empty").classList.toggle("hidden", Boolean(node));
  $("#flow-node-title").textContent = node ? node.data.label || flowNodeLabels[node.data.nodeType] || node.id : "请选择节点";
  if (!node) return;
  $("#flow-node-id").value = node.id;
  $("#flow-node-type").value = node.data.nodeType;
  $("#flow-node-label").value = node.data.label || "";
  $("#flow-node-error").value = node.data.onError || "stop";
  $("#flow-node-config").value = JSON.stringify(flowNodeConfig(node), null, 2);
}

function renderFlowEdgeEditor() {
  const options = state.flowGraph.nodes.map((node) => `<option value="${escapeHtml(node.id)}">${escapeHtml(node.data.label || node.id)}</option>`).join("");
  const sourceValue = $("#flow-edge-source").value; const targetValue = $("#flow-edge-target").value;
  $("#flow-edge-source").innerHTML = options; $("#flow-edge-target").innerHTML = options;
  if (state.flowGraph.nodes.some((node) => node.id === sourceValue)) $("#flow-edge-source").value = sourceValue;
  if (state.flowGraph.nodes.some((node) => node.id === targetValue)) $("#flow-edge-target").value = targetValue;
  const list = $("#flow-edge-list");
  list.classList.toggle("empty-state", state.flowGraph.edges.length === 0);
  list.innerHTML = state.flowGraph.edges.length ? state.flowGraph.edges.map((edge) => `<article class="build-row"><span class="pipeline-state success"></span><div><strong>${escapeHtml(edge.source)} → ${escapeHtml(edge.target)}</strong><small>${escapeHtml(edge.sourceHandle || "default")}</small></div><button class="mini-button danger" type="button" data-flow-edge-remove="${escapeHtml(edge.id)}">移除</button></article>`).join("") : "暂无连线。";
}

function addFlowNode(type) {
  if (type === "trigger") {
    const existing = state.flowGraph.nodes.find((node) => node.data.nodeType === "trigger");
    if (existing) { state.flowNodeActive = existing.id; renderFlowCanvas(); toast("一个 Flow 只能有一个触发器", true); return; }
  }
  const base = type.replace(/[^a-z0-9]/g, "") || "node";
  let index = state.flowGraph.nodes.length + 1; let id = `${base}-${index}`;
  while (state.flowGraph.nodes.some((node) => node.id === id)) id = `${base}-${++index}`;
  const position = { x: 60 + (state.flowGraph.nodes.length % 4) * 220, y: 70 + Math.floor(state.flowGraph.nodes.length / 4) * 130 };
  state.flowGraph.nodes.push({ id, type: "flowNode", position, data: { nodeType: type, label: flowNodeLabels[type] || type, onError: "stop", ...cloneJson(flowNodeDefaults[type] || {}) } });
  state.flowNodeActive = id;
  renderFlowCanvas();
}

function saveFlowNode(event) {
  event.preventDefault();
  const node = state.flowGraph.nodes.find((node) => node.id === state.flowNodeActive);
  if (!node) return;
  let config;
  try { config = JSON.parse($("#flow-node-config").value || "{}"); }
  catch (error) { toast(`节点配置不是有效 JSON：${error.message}`, true); return; }
  if (!config || Array.isArray(config) || typeof config !== "object") { toast("节点配置必须是 JSON 对象", true); return; }
  node.data = { nodeType: node.data.nodeType, label: $("#flow-node-label").value.trim(), onError: $("#flow-node-error").value, ...config };
  renderFlowCanvas(); toast("节点配置已应用到画布");
}

function removeFlowNode() {
  const id = state.flowNodeActive; if (!id) return;
  state.flowGraph.nodes = state.flowGraph.nodes.filter((node) => node.id !== id);
  state.flowGraph.edges = state.flowGraph.edges.filter((edge) => edge.source !== id && edge.target !== id);
  state.flowNodeActive = state.flowGraph.nodes[0]?.id || null; renderFlowCanvas();
}

function flowHasPath(from, to) {
  const seen = new Set(); const stack = [from];
  while (stack.length) { const id = stack.pop(); if (id === to) return true; if (seen.has(id)) continue; seen.add(id); state.flowGraph.edges.filter((edge) => edge.source === id).forEach((edge) => stack.push(edge.target)); }
  return false;
}

function addFlowEdge(event) {
  event.preventDefault();
  const source = $("#flow-edge-source").value, target = $("#flow-edge-target").value;
  if (!source || !target || source === target) { toast("请选择两个不同节点", true); return; }
  if (flowHasPath(target, source)) { toast("这条连线会形成环；重复处理请使用 loop 节点", true); return; }
  const sourceHandle = $("#flow-edge-handle").value.trim() || null;
  if (state.flowGraph.edges.some((edge) => edge.source === source && edge.target === target && (edge.sourceHandle || null) === sourceHandle)) { toast("相同连线已经存在", true); return; }
  state.flowGraph.edges.push({ id: `edge-${Date.now().toString(36)}`, source, target, sourceHandle });
  $("#flow-edge-handle").value = ""; renderFlowCanvas();
}

function applyFlowGraphJson() {
  try { state.flowGraph = normalizeFlowGraph(JSON.parse($("#flow-graph-json").value)); state.flowNodeActive = state.flowGraph.nodes[0]?.id || null; renderFlowCanvas(); toast("FlowGraph 已应用到画布"); }
  catch (error) { toast(`FlowGraph JSON 无效：${error.message}`, true); }
}

function startFlowDrag(event) {
  const element = event.target.closest("[data-flow-node]"); if (!element || event.button !== 0) return;
  const node = state.flowGraph.nodes.find((node) => node.id === element.dataset.flowNode); if (!node) return;
  state.flowNodeActive = node.id; renderFlowNodeInspector();
  $$(".flow-node").forEach((item) => item.classList.toggle("selected", item.dataset.flowNode === node.id));
  const start = { x: event.clientX, y: event.clientY, left: node.position.x, top: node.position.y };
  const move = (moveEvent) => { node.position.x = Math.max(0, Math.round((start.left + moveEvent.clientX - start.x) / 10) * 10); node.position.y = Math.max(0, Math.round((start.top + moveEvent.clientY - start.y) / 10) * 10); element.style.left = `${node.position.x}px`; element.style.top = `${node.position.y}px`; renderFlowEdges(); };
  const up = () => { window.removeEventListener("pointermove", move); window.removeEventListener("pointerup", up); $("#flow-graph-json").value = JSON.stringify(state.flowGraph, null, 2); };
  window.addEventListener("pointermove", move); window.addEventListener("pointerup", up, { once: true });
}

function renderFlowTokens(flow) {
  const tokens = flow?.spec?.tokens || []; const list = $("#flow-token-list");
  list.classList.toggle("empty-state", tokens.length === 0);
  list.innerHTML = tokens.length ? tokens.map((token) => `<article class="build-row"><span class="pipeline-state success"></span><div><strong>${escapeHtml(token.label || "未命名令牌")}</strong><small>尾号 ${escapeHtml(token.last_four)} · ${escapeHtml(new Date(token.created_at_ms).toLocaleString("zh-CN"))}</small><code>${escapeHtml(token.id)}</code></div><button class="mini-button danger" type="button" data-flow-token-revoke="${escapeHtml(token.id)}">撤销</button></article>`).join("") : "暂无 Webhook 令牌。";
}

async function saveFlow(event) {
  event.preventDefault();
  const name = $("#flow-name").value.trim();
  const firstToken = $("#flow-first-token").value.trim();
  const payload = { name, description: $("#flow-description").value.trim(), graph: state.flowGraph, trigger: $("#flow-trigger").value,
    cron: $("#flow-trigger").value === "cron" ? $("#flow-cron").value.trim() : null,
    hostnames: $("#flow-hostnames").value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean),
    retention_days: Number($("#flow-retention").value), max_concurrent_runs: Number($("#flow-concurrency").value),
    alert_webhook_env: $("#flow-alert-env").value.trim() || null, suspended: $("#flow-suspended").checked,
    suspend_reason: $("#flow-suspend-reason").value.trim(), webhook_token_label: firstToken || null };
  try {
    const result = await api("/api/flows", { method: "POST", body: JSON.stringify(payload) });
    if (result.token) { $("#flow-new-token").textContent = result.token; $("#flow-token-reveal").classList.remove("hidden"); }
    const complete = async () => { await loadFlows({ quiet: true }); await selectFlow(name); };
    if (result.pending_approval) showApproval(result, `批准后，Flow ${name} 的图定义将传播到集群。`, complete);
    else { toast(`Flow ${name} 已保存`); await complete(); }
  } catch (error) { toast(error.message, true); }
}

async function mintFlowToken(event) {
  event.preventDefault(); if (!state.flowActive) return;
  try {
    const result = await api(`/api/flows/${encodeURIComponent(state.flowActive)}/tokens`, { method: "POST", body: JSON.stringify({ label: $("#flow-token-label").value.trim() }) });
    $("#flow-new-token").textContent = result.token; $("#flow-token-reveal").classList.remove("hidden"); $("#flow-token-label").value = "";
    const name = state.flowActive; const complete = async () => { await loadFlows({ quiet: true }); await selectFlow(name); };
    if (result.pending_approval) showApproval(result, "批准后，新令牌的哈希将写入签名 Flow 定义。", complete); else await complete();
  } catch (error) { toast(error.message, true); }
}

async function revokeFlowToken(id) {
  if (!state.flowActive || !window.confirm("要撤销此 Flow Webhook 令牌吗？使用它的调用方会立即失去访问权限。")) return;
  try {
    const name = state.flowActive; const result = await api(`/api/flows/${encodeURIComponent(name)}/tokens/${encodeURIComponent(id)}`, { method: "DELETE" });
    const complete = async () => { await loadFlows({ quiet: true }); await selectFlow(name); };
    if (result.pending_approval) showApproval(result, "批准后，令牌哈希将从签名定义移除。", complete); else await complete();
  } catch (error) { toast(error.message, true); }
}

async function triggerFlow(event) {
  event.preventDefault(); if (!state.flowActive) return;
  let input; try { input = JSON.parse($("#flow-input").value); } catch (error) { toast(`输入不是有效 JSON：${error.message}`, true); return; }
  try {
    const data = await api(`/api/flows/${encodeURIComponent(state.flowActive)}/runs`, { method: "POST", body: JSON.stringify({ run_key: $("#flow-run-key").value.trim() || null, input }) });
    toast(`Flow 运行 ${shortId(data.run.id, 20)} 已创建`); await loadFlows({ quiet: true }); await selectFlow(state.flowActive); await openFlowRun(data.run.id);
  } catch (error) { toast(error.message, true); }
}

async function loadFlowRuns() {
  if (!state.flowActive) return;
  try { const data = await api(`/api/flows/${encodeURIComponent(state.flowActive)}/runs?limit=100`); state.flowRuns = data.runs || []; renderFlowRuns(); if (state.flowRunActive && state.flowRuns.some((run) => run.id === state.flowRunActive)) await openFlowRun(state.flowRunActive); }
  catch (error) { toast(error.message, true); }
}

function renderFlowRuns() {
  const list = $("#flow-runs"); list.classList.toggle("empty-state", state.flowRuns.length === 0);
  list.innerHTML = state.flowRuns.length ? state.flowRuns.map((run) => `<button class="build-row" type="button" data-flow-run="${escapeHtml(run.id)}"><span class="pipeline-state ${workflowStatusClass(run.status)}"></span><div><strong>${escapeHtml(run.run_key || shortId(run.id, 24))}</strong><small>${escapeHtml(new Date(run.created_at_ms).toLocaleString("zh-CN"))} · ${escapeHtml(run.trigger)} · 图 v${escapeHtml(run.graph_version)}</small><code>${escapeHtml(run.id)}</code></div><span class="badge">${escapeHtml(flowStatusLabel(run.status))}</span></button>`).join("") : "暂无运行。";
}

async function openFlowRun(id) {
  if (!state.flowActive) return; state.flowRunActive = id;
  try {
    const data = await api(`/api/flows/${encodeURIComponent(state.flowActive)}/runs/${encodeURIComponent(id)}`); if (state.flowRunActive !== id) return;
    const run = data.run; $("#flow-run-panel").classList.remove("hidden"); $("#flow-run-title").textContent = run.run_key || shortId(run.id, 30);
    $("#flow-run-status").textContent = flowStatusLabel(run.status); $("#flow-run-meta").textContent = `${run.id} · 图 v${run.graph_version}${run.error ? ` · ${run.error}` : ""}`;
    const actions = []; if (["queued", "running"].includes(run.status)) actions.push(["cancel", "取消运行"]); if (["complete", "failed", "cancelled"].includes(run.status)) actions.push(["retry", "使用原输入重试"]);
    $("#flow-run-actions").innerHTML = actions.map(([action, label]) => `<button class="${action === "cancel" ? "danger ghost" : "secondary"} compact" type="button" data-flow-action="${action}">${label}</button>`).join("");
    const steps = data.steps || []; $("#flow-steps").classList.toggle("empty-state", steps.length === 0); $("#flow-steps").innerHTML = steps.length ? steps.map((step) => `<article class="build-row ${step.status === "failed" ? "failed" : ""}"><span class="pipeline-state ${workflowStatusClass(step.status)}"></span><div><strong>${escapeHtml(step.seq)}. ${escapeHtml(step.node_id)}</strong><small>${escapeHtml(flowNodeLabels[step.node_type] || step.node_type)} · ${escapeHtml(flowStatusLabel(step.status))}${step.taken ? ` · 出口 ${escapeHtml(step.taken)}` : ""}</small><code>${escapeHtml(step.error || (step.output == null ? "" : JSON.stringify(step.output)))}</code></div></article>`).join("") : "暂无步骤。";
    const events = data.events || []; $("#flow-events").classList.toggle("empty-state", events.length === 0); $("#flow-events").innerHTML = events.length ? events.slice().reverse().map((event) => `<article class="build-row"><span class="pipeline-state active"></span><div><strong>${escapeHtml({ created: "运行已创建", completed: "运行已完成", failed: "运行失败", cancelled: "运行已取消" }[event.kind] || event.kind)}</strong><small>${escapeHtml(new Date(event.created_at_ms).toLocaleString("zh-CN"))} · 序号 ${escapeHtml(event.seq)}</small><code>${escapeHtml(JSON.stringify(event.detail || {}))}</code></div></article>`).join("") : "暂无事件。";
  } catch (error) { toast(error.message, true); }
}

async function runFlowAction(action) {
  if (!state.flowActive || !state.flowRunActive) return;
  if (action === "cancel" && !window.confirm("要取消此 Flow 运行吗？当前未提交节点的结果会被丢弃。")) return;
  try { const name = state.flowActive; const data = await api(`/api/flows/${encodeURIComponent(name)}/runs/${encodeURIComponent(state.flowRunActive)}/${action}`, { method: "POST", body: "{}" }); toast(action === "retry" ? "已创建重试运行" : "运行已取消"); await loadFlows({ quiet: true }); await selectFlow(name); if (action === "retry" && data.result?.id) await openFlowRun(data.result.id); }
  catch (error) { toast(error.message, true); }
}

async function deleteFlow() {
  const name = state.flowActive; if (!name || !window.confirm(`要删除 Flow“${name}”吗？定义将写入可验证墓碑，历史运行按保留策略清理。`)) return;
  try { const result = await api(`/api/flows/${encodeURIComponent(name)}`, { method: "DELETE" }); const complete = async () => { newFlow(); await loadFlows({ quiet: true }); }; if (result.pending_approval) showApproval(result, `批准后，Flow ${name} 将停止接受新运行。`, complete); else await complete(); }
  catch (error) { toast(error.message, true); }
}

function parseNetworkJson(selector, label) {
  try {
    const value = JSON.parse($(selector).value || "{}");
    if (!value || Array.isArray(value) || typeof value !== "object") throw new Error("必须是 JSON 对象");
    return value;
  } catch (error) {
    throw new Error(`${label}无效：${error.message}`);
  }
}

function resetNetworkRuleForm() {
  state.networkRuleActive = null;
  $("#network-rule-form").reset();
  $("#network-rule-name").readOnly = false;
  $("#network-rule-format").value = "auto";
  $("#network-rule-priority").value = "0";
  $("#network-rule-enabled").checked = true;
  $("#network-rule-policies").value = JSON.stringify({
    Proxy: { type: "nearest" },
    DIRECT: { type: "direct" },
    REJECT: { type: "reject" },
  }, null, 2);
  $("#network-rule-providers").value = "{}";
  $("#network-rule-title").textContent = "创建分流规则";
  $("#network-rule-delete").classList.add("hidden");
  renderNetworkRules();
}

function renderNetworkRules() {
  $("#network-rule-count").textContent = String(state.networkRules.length);
  const list = $("#network-rule-list");
  list.classList.toggle("empty-state", state.networkRules.length === 0);
  list.innerHTML = state.networkRules.length ? state.networkRules.map((rule) => {
    const spec = rule.spec || {};
    return `<button class="database-item${rule.name === state.networkRuleActive ? " active" : ""}" type="button" data-network-rule="${escapeHtml(rule.name)}"><span><strong>${escapeHtml(rule.name)}</strong><small>${escapeHtml(spec.description || `${spec.format || "auto"} 规则`)} · 优先级 ${escapeHtml(spec.priority ?? 0)}</small></span><span><span class="badge ${spec.enabled ? "active" : "danger"}">${spec.enabled ? "已启用" : "已停用"}</span> v${escapeHtml(rule.version)}</span></button>`;
  }).join("") : "暂无出口规则。";
}

function selectNetworkRule(name) {
  const rule = state.networkRules.find((item) => item.name === name);
  if (!rule) return;
  state.networkRuleActive = name;
  const spec = rule.spec || {};
  $("#network-rule-name").value = name;
  $("#network-rule-name").readOnly = true;
  $("#network-rule-format").value = spec.format || "auto";
  $("#network-rule-description").value = spec.description || "";
  $("#network-rule-priority").value = String(spec.priority ?? 0);
  $("#network-rule-config").value = spec.config || "";
  $("#network-rule-policies").value = JSON.stringify(spec.policy_exits || {}, null, 2);
  $("#network-rule-providers").value = JSON.stringify(spec.providers || {}, null, 2);
  $("#network-rule-enabled").checked = spec.enabled !== false;
  $("#network-rule-title").textContent = `编辑 ${name}`;
  $("#network-rule-delete").classList.remove("hidden");
  renderNetworkRules();
}

function renderNetworkDeviceRules(selected = []) {
  const box = $("#network-device-rules");
  box.classList.toggle("empty-state", state.networkRules.length === 0);
  box.innerHTML = state.networkRules.length ? state.networkRules.map((rule) => `<label class="check-label compact"><input type="checkbox" value="${escapeHtml(rule.name)}" ${selected.includes(rule.name) ? "checked" : ""}><span>${escapeHtml(rule.name)}${rule.spec?.enabled === false ? "（已停用）" : ""}</span></label>`).join("") : "请先创建分流规则。";
}

function resetNetworkDeviceForm() {
  state.networkDeviceActive = null;
  $("#network-device-form").reset();
  $("#network-device-name").readOnly = false;
  $("#network-device-title").textContent = "注册设备";
  $("#network-device-submit").textContent = "创建并显示令牌";
  $("#network-device-revoke").classList.add("hidden");
  $("#network-device-delete").classList.add("hidden");
  $("#network-token-reveal").classList.add("hidden");
  $("#network-token-value").textContent = "";
  $("#network-device-command").textContent = "";
  renderNetworkDeviceRules([]);
  renderNetworkDevices();
}

function renderNetworkDevices() {
  const active = state.networkDevices.filter((device) => device.active).length;
  $("#network-device-count").textContent = String(active);
  $("#network-device-total").textContent = `共 ${state.networkDevices.length} 台`;
  $("#network-nav-count").textContent = String(active);
  const list = $("#network-device-list");
  list.classList.toggle("empty-state", state.networkDevices.length === 0);
  list.innerHTML = state.networkDevices.length ? state.networkDevices.map((device) => {
    const status = device.revoked_at_ms ? "已撤销" : device.suspended ? "已暂停" : !device.rules_ready ? "等待规则同步" : device.active ? "有效" : "已过期";
    const statusClass = device.active ? "active" : "danger";
    return `<button class="database-item${device.name === state.networkDeviceActive ? " active" : ""}" type="button" data-network-device="${escapeHtml(device.name)}"><span><strong>${escapeHtml(device.label)}</strong><small>${escapeHtml(device.name)} · ${escapeHtml(device.token_prefix)}… · 最近使用 ${escapeHtml(device.last_used_at_ms ? formatDate(device.last_used_at_ms) : "从未")}</small></span><span><span class="badge ${statusClass}">${status}</span> v${escapeHtml(device.version)}</span></button>`;
  }).join("") : "暂无客户端设备。";
}

function selectNetworkDevice(name) {
  const device = state.networkDevices.find((item) => item.name === name);
  if (!device) return;
  const preserveReveal = state.networkDeviceActive === name && Boolean($("#network-token-value").textContent);
  state.networkDeviceActive = name;
  $("#network-device-name").value = device.name;
  $("#network-device-name").readOnly = true;
  $("#network-device-label").value = device.label;
  $("#network-device-expires").value = device.expires_at_ms ? new Date(device.expires_at_ms - new Date().getTimezoneOffset() * 60_000).toISOString().slice(0, 16) : "";
  $("#network-device-suspended").checked = Boolean(device.suspended);
  $("#network-device-title").textContent = `编辑 ${device.label}`;
  $("#network-device-submit").textContent = "保存设备策略";
  $("#network-device-revoke").classList.toggle("hidden", Boolean(device.revoked_at_ms));
  $("#network-device-delete").classList.remove("hidden");
  if (!preserveReveal) {
    $("#network-token-reveal").classList.add("hidden");
    $("#network-token-value").textContent = "";
    $("#network-device-command").textContent = "";
  }
  renderNetworkDeviceRules(device.allowed_rules || []);
  renderNetworkDevices();
}

function renderNetworkExits(exitRole = {}) {
  $("#network-exit-count").textContent = String(state.networkExits.length);
  $("#network-local-role").textContent = exitRole.enabled ? "出口节点" : "仅管理";
  $("#network-local-endpoint").textContent = exitRole.enabled ? (exitRole.advertise || "尚未设置公开端点") : "仅管理签名定义";
  const list = $("#network-exit-list");
  list.classList.toggle("empty-state", state.networkExits.length === 0);
  list.innerHTML = state.networkExits.length ? state.networkExits.map((exit) => `<div class="node-row"><span class="dot ${exit.live ? "online" : "offline"}"></span><div><div class="node-name">${escapeHtml(exit.label || shortId(exit.node_id, 18))}${exit.local ? " · 当前节点" : ""}</div><div class="node-short">${escapeHtml(shortId(exit.node_id, 22))}</div></div><div class="node-address mono">${escapeHtml(exit.endpoint || "端点未公布")}</div><span class="badge active">TLS SOCKS</span></div>`).join("") : "尚未发现出口节点。";
}

async function loadNetwork({ quiet = false } = {}) {
  try {
    const data = await api("/api/network");
    state.networkRules = data.rules || [];
    state.networkDevices = data.devices || [];
    state.networkExits = data.exits || [];
    renderNetworkRules();
    renderNetworkDevices();
    renderNetworkExits(data.exit_role || {});
    if (state.networkRuleActive) {
      const active = state.networkRules.find((rule) => rule.name === state.networkRuleActive);
      if (active) selectNetworkRule(active.name); else resetNetworkRuleForm();
    }
    if (state.networkDeviceActive) {
      const active = state.networkDevices.find((device) => device.name === state.networkDeviceActive);
      if (active) selectNetworkDevice(active.name); else resetNetworkDeviceForm();
    } else renderNetworkDeviceRules([]);
    if (!quiet) toast("设备与出口状态已刷新");
  } catch (error) {
    if (!quiet) toast(error.message, true);
  }
}

async function saveNetworkRule(event) {
  event.preventDefault();
  let policyExits;
  let providers;
  try {
    policyExits = parseNetworkJson("#network-rule-policies", "策略出口映射");
    providers = parseNetworkJson("#network-rule-providers", "规则集快照");
  } catch (error) { return toast(error.message, true); }
  const payload = {
    name: $("#network-rule-name").value.trim(), schema: 1,
    description: $("#network-rule-description").value.trim(), enabled: $("#network-rule-enabled").checked,
    priority: Number($("#network-rule-priority").value), format: $("#network-rule-format").value,
    config: $("#network-rule-config").value, providers, policy_exits: policyExits,
  };
  try {
    const result = await api("/api/network/rules", { method: "POST", body: JSON.stringify(payload) });
    const complete = async () => { state.networkRuleActive = payload.name; await loadNetwork({ quiet: true }); };
    if (result.pending_approval) showApproval(result, `批准出口规则 ${payload.name} 的签名定义。`, complete);
    else { toast("出口规则已保存"); await complete(); }
  } catch (error) { toast(error.message, true); }
}

async function deleteNetworkRule() {
  const name = state.networkRuleActive;
  if (!name || !window.confirm(`要删除出口规则“${name}”吗？被设备引用时系统会拒绝删除。`)) return;
  try {
    const result = await api(`/api/network/rules/${encodeURIComponent(name)}`, { method: "DELETE" });
    const complete = async () => { resetNetworkRuleForm(); await loadNetwork({ quiet: true }); };
    if (result.pending_approval) showApproval(result, `批准删除出口规则 ${name}。`, complete); else await complete();
  } catch (error) { toast(error.message, true); }
}

function selectedNetworkRules() {
  return $$("#network-device-rules input:checked").map((input) => input.value);
}

async function saveNetworkDevice(event) {
  event.preventDefault();
  const expires = $("#network-device-expires").value;
  const allowedRules = selectedNetworkRules();
  if (!allowedRules.length) return toast("请至少选择一条签名分流规则", true);
  const payload = {
    name: $("#network-device-name").value.trim(), label: $("#network-device-label").value.trim(),
    allowed_rules: allowedRules, expires_at_ms: expires ? new Date(expires).getTime() : null,
    suspended: $("#network-device-suspended").checked,
  };
  try {
    const editing = Boolean(state.networkDeviceActive);
    const path = editing ? `/api/network/devices/${encodeURIComponent(payload.name)}` : "/api/network/devices";
    const result = await api(path, { method: editing ? "PATCH" : "POST", body: JSON.stringify(editing ? { label: payload.label, allowed_rules: payload.allowed_rules, expires_at_ms: payload.expires_at_ms, suspended: payload.suspended, revoke: false } : payload) });
    if (result.token) {
      $("#network-token-value").textContent = result.token;
      $("#network-device-command").textContent = `rf device proxy --control ${location.origin} --name ${payload.name} --token-file ~/.rf/devices/${payload.name}.token`;
      $("#network-token-reveal").classList.remove("hidden");
    }
    const complete = async () => { state.networkDeviceActive = payload.name; await loadNetwork({ quiet: true }); };
    if (result.pending_approval) showApproval(result, `批准客户端设备 ${payload.name} 的签名凭据。`, complete);
    else { toast(editing ? "设备策略已保存" : "设备已注册"); await complete(); }
  } catch (error) { toast(error.message, true); }
}

async function revokeNetworkDevice() {
  const device = state.networkDevices.find((item) => item.name === state.networkDeviceActive);
  if (!device || !window.confirm(`立即撤销“${device.label}”的令牌吗？此操作不可恢复。`)) return;
  const payload = { label: device.label, allowed_rules: device.allowed_rules || [], expires_at_ms: device.expires_at_ms, suspended: true, revoke: true };
  try {
    const result = await api(`/api/network/devices/${encodeURIComponent(device.name)}`, { method: "PATCH", body: JSON.stringify(payload) });
    const complete = () => loadNetwork({ quiet: true });
    if (result.pending_approval) showApproval(result, `批准撤销客户端设备 ${device.name}。`, complete); else await complete();
  } catch (error) { toast(error.message, true); }
}

async function deleteNetworkDevice() {
  const name = state.networkDeviceActive;
  if (!name || !window.confirm(`要从签名目录中删除设备“${name}”吗？`)) return;
  try {
    const result = await api(`/api/network/devices/${encodeURIComponent(name)}`, { method: "DELETE" });
    const complete = async () => { resetNetworkDeviceForm(); await loadNetwork({ quiet: true }); };
    if (result.pending_approval) showApproval(result, `批准删除客户端设备 ${name}。`, complete); else await complete();
  } catch (error) { toast(error.message, true); }
}

function emailBooleanLabel(value, optional = false) {
  if (optional && value == null) return "未检查";
  return value ? "通过" : "未通过";
}

function emailStatusLabel(status) {
  return {
    received: "已接收", processing: "处理中", delivered: "已交付", forwarded: "已转发",
    queued: "排队中", sending: "发送中", sent: "已发送", rejected: "已拒绝",
    failed: "失败", dropped: "已丢弃", deferred: "稍后重试",
  }[status] || status || "未知";
}

function emailRouteSummary(route) {
  const matcher = route.match === "exact" ? `精确 ${route.value}`
    : route.match === "prefix" ? `前缀 ${route.value}` : "兜底";
  const destination = route.destination?.type === "worker" ? `Worker ${route.destination.worker}`
    : route.destination?.type === "forward" ? `转发至 ${(route.destination.addresses || []).join(", ")}`
      : "直接丢弃";
  return `${matcher} → ${destination}`;
}

function updateEmailContextOptions(selectedBucket = "", selectedWorker = "") {
  const buckets = state.emailContext.buckets || [];
  const workers = state.emailContext.workers || [];
  $("#email-bucket").innerHTML = '<option value="">请选择 bucket</option>' + buckets.map((item) => {
    const name = item.name || item;
    return `<option value="${escapeHtml(name)}"${name === selectedBucket ? " selected" : ""}>${escapeHtml(name)}</option>`;
  }).join("");
  $("#email-route-worker").innerHTML = '<option value="">请选择 Worker</option>' + workers.map((item) => {
    const name = item.name || item;
    return `<option value="${escapeHtml(name)}"${name === selectedWorker ? " selected" : ""}>${escapeHtml(name)}</option>`;
  }).join("");
}

function fillEmailDomainForm(domain) {
  const spec = domain?.spec || {};
  $("#email-name").value = domain?.name || "";
  $("#email-name").readOnly = Boolean(domain);
  $("#email-domain").value = spec.domain || "";
  $("#email-mx").value = spec.mx_hostname || state.emailContext.email_node?.mx_hostname || "";
  updateEmailContextOptions(spec.bucket || "", $("#email-route-worker").value);
  $("#email-prefix").value = spec.object_prefix || "mail";
  $("#email-description").value = spec.description || "";
  $("#email-max-size").value = Math.max(1, Math.round(Number(spec.max_message_bytes || 25 * 1024 * 1024) / 1024 / 1024));
  $("#email-retention").value = spec.retention_days || 30;
  $("#email-inbound-rate").value = spec.inbound_per_minute || 1000;
  $("#email-outbound-rate").value = spec.outbound_per_minute || 1000;
  $("#email-dkim-selector").value = spec.dkim_selector || "rf";
  $("#email-dkim-public").value = spec.dkim_public_key || "";
  $("#email-dkim-env").value = spec.dkim_private_key_env || "";
  $("#email-suspended").checked = Boolean(spec.suspended);
  $("#email-suspend-reason").value = spec.suspend_reason || "";
  $("#email-rotate-verification").checked = false;
}

function resetEmailDomainForm() {
  state.emailActive = null;
  state.emailRoutes = [];
  state.emailMessages = [];
  state.emailMessageActive = null;
  $("#email-domain-form").reset();
  fillEmailDomainForm(null);
  renderEmailRoutes();
  ["#email-dns-panel", "#email-routes-panel", "#email-send-panel", "#email-message-panel", "#email-messages-panel"].forEach((id) => $(id).classList.add("hidden"));
  $("#email-delete").classList.add("hidden");
  $("#email-verify").classList.add("hidden");
  $("#email-active-name").textContent = "请选择邮件域";
  $("#email-summary").textContent = "选择后可配置 DNS、编辑路由并查看收发记录。";
}

function renderEmailDomains() {
  $("#email-count").textContent = `${state.emailDomains.length} 个邮件域`;
  $("#email-nav-count").textContent = String(state.emailDomains.length);
  const list = $("#email-domain-list");
  list.classList.toggle("empty-state", state.emailDomains.length === 0);
  list.innerHTML = state.emailDomains.length ? state.emailDomains.map((domain) => {
    const active = state.emailActive === domain.name ? " active" : "";
    const verified = domain.verification?.verified;
    const status = domain.spec?.suspended ? "已暂停" : verified ? "DNS 已验证" : "等待 DNS";
    return `<button class="database-item${active}" type="button" data-email-domain="${escapeHtml(domain.name)}"><span><strong>${escapeHtml(domain.name)}</strong><small>${escapeHtml(domain.spec?.domain || "未配置域名")} · ${escapeHtml(status)}</small></span><span>v${escapeHtml(domain.version)}</span></button>`;
  }).join("") : "暂无邮件域。";
}

function renderEmailRoutes() {
  const list = $("#email-route-list");
  const routes = [...state.emailRoutes].sort((a, b) => Number(a.priority || 0) - Number(b.priority || 0));
  list.classList.toggle("empty-state", routes.length === 0);
  list.innerHTML = routes.length ? routes.map((route) => `<article class="build-row"><span class="pipeline-state ${route.enabled === false ? "failed" : "active"}"></span><div><strong>${escapeHtml(route.id)} · 优先级 ${escapeHtml(route.priority || 0)}</strong><small>${escapeHtml(emailRouteSummary(route))}${route.enabled === false ? " · 已停用" : ""}</small></div><button class="mini-button" type="button" data-email-route-edit="${escapeHtml(route.id)}">编辑</button><button class="mini-button danger" type="button" data-email-route-remove="${escapeHtml(route.id)}">移除</button></article>`).join("") : "暂无路由。";
}

function updateEmailRouteFields() {
  const match = $("#email-route-match").value;
  const destination = $("#email-route-destination").value;
  $("#email-route-value-label").classList.toggle("hidden", match === "catch_all");
  $("#email-route-value").required = match !== "catch_all";
  $("#email-route-target-label").classList.toggle("hidden", destination === "drop");
  $("#email-route-worker").classList.toggle("hidden", destination !== "worker");
  $("#email-route-addresses").classList.toggle("hidden", destination !== "forward");
  $("#email-route-worker").required = destination === "worker";
  $("#email-route-addresses").required = destination === "forward";
}

function fillEmailRouteForm(route) {
  if (!route) return;
  $("#email-route-id").value = route.id;
  $("#email-route-priority").value = route.priority || 0;
  $("#email-route-match").value = route.match;
  $("#email-route-value").value = route.value || "";
  $("#email-route-destination").value = route.destination?.type || "worker";
  $("#email-route-worker").value = route.destination?.worker || "";
  $("#email-route-addresses").value = (route.destination?.addresses || []).join(", ");
  $("#email-route-enabled").checked = route.enabled !== false;
  updateEmailRouteFields();
}

function saveEmailRoute(event) {
  event.preventDefault();
  const match = $("#email-route-match").value;
  const destinationType = $("#email-route-destination").value;
  const route = {
    id: $("#email-route-id").value.trim(), priority: Number($("#email-route-priority").value),
    enabled: $("#email-route-enabled").checked, match,
    destination: destinationType === "worker" ? { type: "worker", worker: $("#email-route-worker").value }
      : destinationType === "forward" ? { type: "forward", addresses: $("#email-route-addresses").value.split(",").map((value) => value.trim().toLowerCase()).filter(Boolean) }
        : { type: "drop" },
  };
  if (match !== "catch_all") route.value = $("#email-route-value").value.trim().toLowerCase();
  state.emailRoutes = state.emailRoutes.filter((item) => item.id !== route.id).concat(route);
  renderEmailRoutes();
  event.target.reset();
  $("#email-route-enabled").checked = true;
  updateEmailRouteFields();
}

function renderEmailDns(domain) {
  const spec = domain.spec || {};
  const verification = domain.verification;
  const records = [
    ["TXT（所有权）", spec.ownership_name || `_randallflare-verify.${spec.domain}`, spec.ownership_value || `rf-email-verification=${spec.verification_challenge}`],
    ["MX", spec.domain, spec.mx_hostname],
    ["TXT（SPF）", spec.domain, "v=spf1 mx -all"],
  ];
  if (spec.dkim_public_key) records.push(["TXT（DKIM）", `${spec.dkim_selector}._domainkey.${spec.domain}`, spec.dkim_public_key]);
  $("#email-dns-records").innerHTML = records.map(([kind, name, value]) => `<div><dt>${escapeHtml(kind)} · ${escapeHtml(name)}</dt><dd class="mono">${escapeHtml(value)}</dd></div>`).join("");
  $("#email-ownership-state").textContent = emailBooleanLabel(verification?.ownership_ok, true);
  $("#email-mx-state").textContent = emailBooleanLabel(verification?.mx_ok, true);
  $("#email-dkim-state").textContent = spec.dkim_public_key ? emailBooleanLabel(verification?.dkim_ok, true) : "未配置";
  $("#email-verified-state").textContent = verification?.verified ? "已就绪" : "待验证";
  const detail = $("#email-verification-detail");
  detail.classList.toggle("hidden", !verification);
  detail.classList.toggle("error", Boolean(verification?.error));
  if (verification) detail.textContent = verification.error || `最近检查：${new Date(verification.checked_at_ms).toLocaleString("zh-CN")}；SPF ${verification.spf_present ? "已发现" : "未发现（建议配置）"}。`;
}

async function loadEmail({ quiet = false } = {}) {
  try {
    const data = await api("/api/email");
    state.emailDomains = data.domains || [];
    state.emailContext = { buckets: data.buckets || [], workers: data.workers || [], email_node: data.email_node || null };
    const warning = $("#email-node-warning");
    warning.textContent = "当前节点未启用 SMTP 邮件角色。你仍可管理签名定义和查看集群数据，但入站接收需要至少一个邮件节点。";
    warning.classList.toggle("hidden", Boolean(data.email_node?.enabled));
    updateEmailContextOptions($("#email-bucket").value, $("#email-route-worker").value);
    if (!state.emailActive && !$("#email-name").value) fillEmailDomainForm(null);
    renderEmailDomains();
    if (state.emailActive) {
      const active = state.emailDomains.find((item) => item.name === state.emailActive);
      if (active) await selectEmailDomain(active.name, { loadMessages: false }); else resetEmailDomainForm();
    }
    if (!quiet) toast("邮件域已刷新");
  } catch (error) {
    const warning = $("#email-node-warning");
    warning.textContent = `连接节点尚未提供邮件资源接口：${error.message}。请先把该节点升级到包含邮件能力的版本。`;
    warning.classList.remove("hidden");
    if (!quiet) toast(error.message, true);
  }
}

async function selectEmailDomain(name, { loadMessages = true } = {}) {
  const domain = state.emailDomains.find((item) => item.name === name);
  if (!domain) return;
  state.emailActive = name;
  state.emailRoutes = structuredClone(domain.spec?.routes || []);
  state.emailMessageActive = null;
  fillEmailDomainForm(domain);
  renderEmailDomains();
  renderEmailRoutes();
  renderEmailDns(domain);
  $("#email-active-name").textContent = domain.spec.domain;
  $("#email-summary").textContent = `${domain.name} · v${domain.version} · R2 ${domain.spec.bucket}/${domain.spec.object_prefix}`;
  ["#email-dns-panel", "#email-routes-panel", "#email-send-panel", "#email-messages-panel"].forEach((id) => $(id).classList.remove("hidden"));
  $("#email-message-panel").classList.add("hidden");
  $("#email-delete").classList.remove("hidden");
  $("#email-verify").classList.remove("hidden");
  $("#email-send-from").value = `noreply@${domain.spec.domain}`;
  if (loadMessages) await loadEmailMessages();
}

async function saveEmailDomain(event) {
  event.preventDefault();
  const payload = {
    name: $("#email-name").value.trim(), description: $("#email-description").value.trim(),
    domain: $("#email-domain").value.trim().toLowerCase().replace(/\.$/, ""),
    mx_hostname: $("#email-mx").value.trim().toLowerCase().replace(/\.$/, ""), bucket: $("#email-bucket").value,
    object_prefix: $("#email-prefix").value.trim(), routes: state.emailRoutes,
    max_message_bytes: Number($("#email-max-size").value) * 1024 * 1024,
    inbound_per_minute: Number($("#email-inbound-rate").value), outbound_per_minute: Number($("#email-outbound-rate").value),
    retention_days: Number($("#email-retention").value), dkim_selector: $("#email-dkim-selector").value.trim(),
    dkim_public_key: $("#email-dkim-public").value.trim(), dkim_private_key_env: $("#email-dkim-env").value.trim(),
    rotate_verification: $("#email-rotate-verification").checked, suspended: $("#email-suspended").checked,
    suspend_reason: $("#email-suspend-reason").value.trim(),
  };
  try {
    const result = await api("/api/email", { method: "POST", body: JSON.stringify(payload) });
    const complete = async () => { await loadEmail({ quiet: true }); await selectEmailDomain(payload.name); };
    if (result.pending_approval) showApproval(result, `批准邮件域 ${payload.domain} 的签名定义。`, complete);
    else { toast("邮件域定义已保存"); await complete(); }
  } catch (error) { toast(error.message, true); }
}

async function verifyEmailDomain() {
  if (!state.emailActive) return;
  try {
    const data = await api(`/api/email/${encodeURIComponent(state.emailActive)}/verification`, { method: "POST", body: "{}" });
    const domain = state.emailDomains.find((item) => item.name === state.emailActive);
    if (domain) { domain.verification = data.verification; renderEmailDns(domain); renderEmailDomains(); }
    toast(data.verification?.verified ? "DNS 验证已全部通过" : "DNS 尚未完全生效");
  } catch (error) { toast(error.message, true); }
}

async function deleteEmailDomain() {
  const name = state.emailActive;
  if (!name || !window.confirm(`要删除邮件域“${name}”吗？新邮件将停止接收，既有审计记录按保留策略处理。`)) return;
  try {
    const result = await api(`/api/email/${encodeURIComponent(name)}`, { method: "DELETE" });
    const complete = async () => { resetEmailDomainForm(); await loadEmail({ quiet: true }); };
    if (result.pending_approval) showApproval(result, `批准删除邮件域 ${name}。`, complete); else await complete();
  } catch (error) { toast(error.message, true); }
}

function renderEmailMessages() {
  const list = $("#email-message-list");
  list.classList.toggle("empty-state", state.emailMessages.length === 0);
  list.innerHTML = state.emailMessages.length ? state.emailMessages.map((message) => `<button class="build-row" type="button" data-email-message="${escapeHtml(message.id)}"><span class="pipeline-state ${["failed", "rejected"].includes(message.status) ? "failed" : message.status === "sent" || message.status === "delivered" ? "complete" : "active"}"></span><div><strong>${escapeHtml(message.subject || "（无主题）")}</strong><small>${message.direction === "inbound" ? "入站" : "出站"} · ${escapeHtml(message.mail_from || "空信封发件人")} → ${escapeHtml(message.rcpt_to)} · ${escapeHtml(new Date(message.created_at_ms).toLocaleString("zh-CN"))}</small><code>${escapeHtml(message.last_error || message.id)}</code></div><span class="badge">${escapeHtml(emailStatusLabel(message.status))}</span></button>`).join("") : "暂无邮件记录。";
}

async function loadEmailMessages() {
  if (!state.emailActive) return;
  try {
    const data = await api(`/api/email/${encodeURIComponent(state.emailActive)}/messages?limit=200`);
    state.emailMessages = data.messages || [];
    renderEmailMessages();
  } catch (error) { toast(error.message, true); }
}

async function openEmailMessage(id) {
  if (!state.emailActive) return;
  try {
    const data = await api(`/api/email/${encodeURIComponent(state.emailActive)}/messages/${encodeURIComponent(id)}`);
    const message = data.message;
    state.emailMessageActive = id;
    $("#email-message-panel").classList.remove("hidden");
    $("#email-message-title").textContent = message.subject || "（无主题）";
    const fields = [["方向", message.direction === "inbound" ? "入站" : "出站"], ["状态", emailStatusLabel(message.status)], ["信封发件人", message.mail_from || "空"], ["信封收件人", message.rcpt_to], ["大小", formatBytes(message.size)], ["尝试次数", message.attempts], ["SPF / DKIM / DMARC", [message.spf, message.dkim, message.dmarc].filter(Boolean).join(" / ") || "无"], ["R2 对象", message.object_key], ["SHA-256", message.sha256], ["最后错误", message.last_error || "无"]];
    $("#email-message-detail").innerHTML = fields.map(([key, value]) => `<div><dt>${escapeHtml(key)}</dt><dd class="${key === "R2 对象" || key === "SHA-256" ? "mono" : ""}">${escapeHtml(value)}</dd></div>`).join("");
    const download = $("#email-message-download");
    download.href = `/api/email/${encodeURIComponent(state.emailActive)}/messages/${encodeURIComponent(id)}/raw`;
    download.classList.remove("hidden");
  } catch (error) { toast(error.message, true); }
}

async function sendEmailMessage(event) {
  event.preventDefault();
  if (!state.emailActive) return;
  const rawBytes = new TextEncoder().encode($("#email-send-raw").value);
  const payload = { mail_from: $("#email-send-from").value.trim().toLowerCase(), recipients: $("#email-send-to").value.split(",").map((value) => value.trim().toLowerCase()).filter(Boolean), raw_base64: bytesToBase64(rawBytes) };
  try {
    const data = await api(`/api/email/${encodeURIComponent(state.emailActive)}/messages`, { method: "POST", body: JSON.stringify(payload) });
    toast(`已持久化并排队 ${data.queued?.length || 0} 封邮件`);
    await loadEmailMessages();
  } catch (error) { toast(error.message, true); }
}

function binaryStorageLabel(storage) {
  if (storage?.type === "rclone") {
    const prefix = storage.prefix ? `/${storage.prefix}` : "";
    return `rclone ${storage.remote}:${prefix}`;
  }
  return "本地内容存储";
}

function renderBinaries() {
  $("#binary-count").textContent = `${state.binaries.length} 个程序`;
  $("#binary-nav-count").textContent = String(state.binaries.length);
  const list = $("#binary-list");
  list.classList.toggle("empty-state", state.binaries.length === 0);
  list.innerHTML = state.binaries.length
    ? state.binaries.map((binary) => {
      const spec = binary.spec || {};
      const active = binary.name === state.binaryActive ? " active" : "";
      const stateCopy = spec.suspended ? "已暂停" : "可执行";
      return `<button class="database-item${active}" type="button" data-binary="${escapeHtml(binary.name)}"><span><strong>${escapeHtml(binary.name)}</strong><small>${escapeHtml(spec.description || spec.os_arch || "Binary Deliver")} · ${escapeHtml(formatBytes(spec.size_bytes))}</small></span><span><span class="badge ${spec.suspended ? "danger" : "active"}">${stateCopy}</span> v${escapeHtml(binary.version)}</span></button>`;
    }).join("")
    : "暂无 Binary Deliver 程序。";
}

function toggleBinaryStorageFields() {
  const rclone = $("#binary-storage-backend").value === "rclone";
  $("#binary-rclone-remote-label").classList.toggle("hidden", !rclone);
  $("#binary-rclone-prefix-label").classList.toggle("hidden", !rclone);
  $("#binary-rclone-remote").required = rclone;
}

function resetBinaryForm() {
  state.binaryActive = null;
  $("#binary-form").reset();
  $("#binary-name").readOnly = false;
  $("#binary-os-arch").value = state.binaryContext.current_os_arch || "linux/amd64";
  $("#binary-timeout").value = "30000";
  $("#binary-stdin-limit").value = String(10 * 1024 * 1024);
  $("#binary-output-limit").value = String(10 * 1024 * 1024);
  $("#binary-storage-backend").value = "local";
  $("#binary-editor-title").textContent = "上传程序";
  $("#binary-editor-summary").textContent = "新文件会先存入内容地址存储，再等待管理员批准它的 SHA-256 和执行权限。";
  $("#binary-submit").textContent = "上传并提交签名";
  $("#binary-delete").classList.add("hidden");
  $("#binary-current").classList.add("hidden");
  $("#binary-upload-progress").classList.add("hidden");
  $("#binary-upload-bar").style.width = "0%";
  toggleBinaryStorageFields();
  renderBinaries();
}

function fillBinaryForm(binary) {
  const spec = binary.spec || {};
  const storage = spec.storage || { type: "local" };
  state.binaryActive = binary.name;
  $("#binary-name").value = binary.name;
  $("#binary-name").readOnly = true;
  $("#binary-description").value = spec.description || "";
  $("#binary-file").value = "";
  $("#binary-os-arch").value = spec.os_arch || state.binaryContext.current_os_arch || "linux/amd64";
  $("#binary-storage-backend").value = storage.type || "local";
  $("#binary-rclone-remote").value = storage.remote || "";
  $("#binary-rclone-prefix").value = storage.prefix || "";
  $("#binary-timeout").value = String(spec.default_timeout_ms ?? 30000);
  $("#binary-stdin-limit").value = String(spec.max_stdin_bytes ?? 10 * 1024 * 1024);
  $("#binary-output-limit").value = String(spec.max_output_bytes ?? 10 * 1024 * 1024);
  $("#binary-required-tags").value = (spec.required_tags || []).join("\n");
  $("#binary-network").checked = Boolean(spec.allow_network);
  $("#binary-r2").checked = Boolean(spec.allow_r2);
  $("#binary-suspended").checked = Boolean(spec.suspended);
  $("#binary-editor-title").textContent = binary.name;
  $("#binary-editor-summary").textContent = `签名定义 v${binary.version}。留空文件只更新沙箱策略；选择文件会产生新的不可变摘要。`;
  $("#binary-submit").textContent = "保存策略或替换文件";
  $("#binary-delete").classList.remove("hidden");
  $("#binary-current").classList.remove("hidden");
  const details = [
    ["SHA-256", spec.sha256 || "—"],
    ["文件大小", formatBytes(spec.size_bytes)],
    ["存储位置", binaryStorageLabel(storage)],
    ["目标架构", spec.os_arch || "—"],
    ["网络", spec.allow_network ? "允许（服从集群策略）" : "隔离"],
    ["R2 输出", spec.allow_r2 ? "允许" : "禁止"],
    ["节点标签", (spec.required_tags || []).join(", ") || "无"],
    ["资源版本", `v${binary.version}`],
  ];
  $("#binary-current-detail").innerHTML = details.map(([key, value]) => `<div><dt>${escapeHtml(key)}</dt><dd class="${key === "SHA-256" ? "mono" : ""}">${escapeHtml(value)}</dd></div>`).join("");
  toggleBinaryStorageFields();
  renderBinaries();
}

async function loadBinaries({ quiet = false } = {}) {
  try {
    const data = await api("/api/binaries");
    state.binaries = data.binaries || [];
    state.binaryContext = data;
    const rcloneOption = $('#binary-storage-backend option[value="rclone"]');
    if (rcloneOption) rcloneOption.disabled = !Boolean(data.capabilities?.rclone);
    renderBinaries();
    if (state.binaryActive) {
      const current = state.binaries.find((item) => item.name === state.binaryActive);
      if (current) fillBinaryForm(current); else resetBinaryForm();
    }
  } catch (error) {
    if (!quiet) toast(error.message, true);
  }
}

function selectBinary(name) {
  const binary = state.binaries.find((item) => item.name === name);
  if (!binary) return;
  fillBinaryForm(binary);
}

function uploadBinaryBlob(file) {
  return new Promise((resolve, reject) => {
    const params = new URLSearchParams({ storage_backend: $("#binary-storage-backend").value });
    if ($("#binary-storage-backend").value === "rclone") {
      params.set("rclone_remote", $("#binary-rclone-remote").value.trim());
      params.set("rclone_prefix", $("#binary-rclone-prefix").value.trim());
    }
    const xhr = new XMLHttpRequest();
    xhr.open("POST", `/api/binaries/blob?${params}`);
    xhr.withCredentials = true;
    xhr.setRequestHeader("content-type", "application/octet-stream");
    if (consoleMode === "local") xhr.setRequestHeader("x-rf-console-token", token);
    if (consoleMode === "public" && state.session?.csrf) xhr.setRequestHeader("x-rf-csrf", state.session.csrf);
    xhr.upload.onprogress = (event) => {
      if (!event.lengthComputable) return;
      const percent = Math.min(100, Math.round(event.loaded / event.total * 100));
      $("#binary-upload-percent").textContent = `${percent}%`;
      $("#binary-upload-label").textContent = percent === 100 ? "正在校验并持久化…" : `正在上传 ${file.name}`;
      $("#binary-upload-bar").style.width = `${percent}%`;
    };
    xhr.onerror = () => reject(new Error("Binary 上传连接中断"));
    xhr.onload = () => {
      let payload;
      try { payload = JSON.parse(xhr.responseText || "{}"); }
      catch { payload = xhr.responseText; }
      if (xhr.status >= 200 && xhr.status < 300) resolve(payload);
      else reject(new Error(payload?.error || payload || `上传失败（HTTP ${xhr.status}）`));
    };
    $("#binary-upload-progress").classList.remove("hidden");
    $("#binary-upload-percent").textContent = "0%";
    $("#binary-upload-label").textContent = `正在上传 ${file.name}`;
    $("#binary-upload-bar").style.width = "0%";
    setBusy(true);
    xhr.addEventListener("loadend", () => setBusy(false), { once: true });
    xhr.send(file);
  });
}

async function saveBinary(event) {
  event.preventDefault();
  const file = $("#binary-file").files?.[0];
  if (file && file.size > 200 * 1024 * 1024) {
    toast("Binary 文件不能超过 200 MiB", true);
    return;
  }
  const current = state.binaries.find((item) => item.name === state.binaryActive);
  if (!file && !current) {
    toast("首次创建 Binary 必须选择可执行文件", true);
    return;
  }
  try {
    let blob = file ? await uploadBinaryBlob(file) : {
      sha256: current.spec.sha256,
      size_bytes: current.spec.size_bytes,
      storage: current.spec.storage,
    };
    if (!file) {
      const requestedBackend = $("#binary-storage-backend").value;
      if ((blob.storage?.type || "local") !== requestedBackend) {
        throw new Error("变更存储后端时请重新选择文件，以便写入新的内容存储");
      }
      if (requestedBackend === "rclone" && (blob.storage.remote !== $("#binary-rclone-remote").value.trim() || (blob.storage.prefix || "") !== $("#binary-rclone-prefix").value.trim())) {
        throw new Error("变更 rclone 位置时请重新选择文件，以便写入新的内容存储");
      }
    }
    const payload = {
      name: $("#binary-name").value.trim(),
      description: $("#binary-description").value.trim(),
      sha256: blob.sha256,
      size_bytes: blob.size_bytes,
      storage: blob.storage,
      os_arch: $("#binary-os-arch").value,
      default_timeout_ms: Number($("#binary-timeout").value),
      max_stdin_bytes: Number($("#binary-stdin-limit").value),
      max_output_bytes: Number($("#binary-output-limit").value),
      allow_network: $("#binary-network").checked,
      allow_r2: $("#binary-r2").checked,
      required_tags: $("#binary-required-tags").value.split(/\r?\n/).map((value) => value.trim()).filter(Boolean),
      suspended: $("#binary-suspended").checked,
    };
    const result = await api("/api/binaries", { method: "POST", body: JSON.stringify(payload) });
    const complete = async () => { await loadBinaries({ quiet: true }); selectBinary(payload.name); await loadOverview({ quiet: true }); };
    if (result.pending_approval) showApproval(result, `批准 Binary Deliver ${payload.name} 的内容摘要与沙箱策略。`, complete);
    else { toast(`Binary Deliver ${payload.name} 已保存`); await complete(); }
  } catch (error) {
    toast(error.message, true);
  } finally {
    $("#binary-upload-progress").classList.add("hidden");
  }
}

async function deleteBinary() {
  const name = state.binaryActive;
  if (!name || !window.confirm(`要删除 Binary Deliver“${name}”吗？仍被 Worker 绑定时，集群会拒绝删除。`)) return;
  try {
    const result = await api(`/api/binaries/${encodeURIComponent(name)}`, { method: "DELETE" });
    const complete = async () => { resetBinaryForm(); await loadBinaries({ quiet: true }); await loadOverview({ quiet: true }); };
    if (result.pending_approval) showApproval(result, `批准删除 Binary Deliver ${name}。`, complete);
    else { toast(`Binary Deliver ${name} 已删除`); await complete(); }
  } catch (error) { toast(error.message, true); }
}

const scopeAreaCopy = {
  worker: ["Worker", "项目、部署与日志"],
  kv: ["KV", "键值命名空间"],
  d1: ["D1", "SQL 数据库"],
  r2: ["R2", "bucket 与对象"],
  queue: ["队列", "消息与死信"],
  analytics: ["Analytics", "事件与聚合"],
  pipeline: ["Pipeline", "摄取与批次"],
  workflow: ["Workflow", "实例与信号"],
  flow: ["Flow", "定义与运行"],
  email: ["邮件", "域名与消息"],
  binary: ["Binary", "原生程序、内容与策略"],
  storage: ["存储策略", "默认后端与 rclone 分片"],
  network: ["设备网络", "规则、设备与出口目录"],
  node: ["节点", "成员与调度"],
  quota: ["配额", "集群安全策略"],
  audit: ["审计", "签名透明日志"],
};

function credentialWritesAllowed() {
  return consoleMode === "public" && Boolean(state.session?.secure_transport);
}

function renderSecurity() {
  const data = state.security;
  if (!data) return;
  const quota = data.quota || {};
  const usage = data.usage || {};
  $("#security-worker-usage").textContent = String(usage.workers ?? 0);
  $("#security-worker-limit").textContent = `配额 ${quota.max_workers ?? "—"}`;
  $("#security-hostname-usage").textContent = String(usage.custom_hostnames ?? 0);
  $("#security-hostname-limit").textContent = `配额 ${quota.max_custom_hostnames ?? "—"}`;
  $("#security-r2-byte-usage").textContent = formatBytes(usage.r2_local_bytes || 0);
  $("#security-r2-byte-limit").textContent = `配额 ${formatBytes(quota.max_r2_local_bytes || 0)}`;
  $("#security-r2-object-usage").textContent = String(usage.r2_objects ?? 0);
  $("#security-r2-object-limit").textContent = `配额 ${quota.max_r2_objects ?? "—"}`;
  if (!state.securityDirty) {
    $("#quota-workers").value = quota.max_workers ?? "";
    $("#quota-hostnames").value = quota.max_custom_hostnames ?? "";
    $("#quota-worker-bytes").value = quota.max_worker_bytes ?? "";
    $("#quota-requests").value = quota.max_requests_per_minute ?? "";
    $("#quota-r2-bytes").value = quota.max_r2_local_bytes ?? "";
    $("#quota-r2-objects").value = quota.max_r2_objects ?? "";
    $("#quota-outbound").checked = Boolean(quota.worker_outbound_allowed);
  }
  const selectedScopes = new Set(
    $$("#access-token-scopes input:checked").map((input) => input.value),
  );
  const availableScopes = new Set(data.scopes || []);
  const disabled = credentialWritesAllowed() ? "" : "disabled";
  const wildcard = availableScopes.has("*")
    ? `<div class="scope-group wildcard"><span><strong>全部权限</strong><small>仅授予完全受信任的自动化</small></span><label class="scope-choice"><input type="checkbox" value="*" ${selectedScopes.has("*") ? "checked" : ""} ${disabled}><span>启用 *</span></label></div>`
    : "";
  const grouped = Object.entries(scopeAreaCopy).map(([area, copy]) => {
    const read = `${area}:read`;
    const write = `${area}:write`;
    if (!availableScopes.has(read) && !availableScopes.has(write)) return "";
    return `<div class="scope-group"><span><strong>${escapeHtml(copy[0])}</strong><small>${escapeHtml(copy[1])}</small></span><div class="scope-actions">${availableScopes.has(read) ? `<label class="scope-choice"><input type="checkbox" value="${escapeHtml(read)}" ${selectedScopes.has(read) ? "checked" : ""} ${disabled}><span>读取</span></label>` : ""}${availableScopes.has(write) ? `<label class="scope-choice"><input type="checkbox" value="${escapeHtml(write)}" ${selectedScopes.has(write) ? "checked" : ""} ${disabled}><span>写入</span></label>` : ""}</div></div>`;
  }).join("");
  $("#access-token-scopes").innerHTML = wildcard + grouped;
  renderAccessTokens(data.access_tokens || []);
  const editing = state.s3Editing
    ? (data.s3_credentials || []).find((item) => item.id === state.s3Editing)
    : null;
  renderS3GrantList(editing?.grants || null);
  renderS3Credentials(data.s3_credentials || []);
  $("#s3-endpoint").textContent = `${location.origin}${data.s3_endpoint || "/s3"}`;
}

function renderAccessTokens(tokens) {
  const box = $("#access-token-list");
  box.classList.toggle("empty-state", tokens.length === 0);
  box.innerHTML = tokens.length ? tokens.map((item) => `<div class="database-row"><div><strong>${escapeHtml(item.label)}</strong><small><code>${escapeHtml(item.prefix)}…</code> · ${item.active ? "有效" : item.revoked_at_ms ? "已撤销" : "已过期"}</small><div class="tag-row">${(item.scopes || []).map((scope) => `<span class="badge">${escapeHtml(scope)}</span>`).join("")}</div><small>创建 ${escapeHtml(formatDate(item.created_at_ms))} · 最近使用 ${escapeHtml(item.last_used_at_ms ? formatDate(item.last_used_at_ms) : "从未")}${item.expires_at_ms ? ` · 到期 ${escapeHtml(formatDate(item.expires_at_ms))}` : ""}</small></div>${item.active ? `<button class="mini-button danger" type="button" data-token-revoke="${escapeHtml(item.id)}">撤销</button>` : '<span class="badge">不可用</span>'}</div>`).join("") : "暂无访问令牌。";
}

function renderS3GrantList(grants = null) {
  const buckets = state.r2Buckets || [];
  const acl = $("#s3-acl-enabled").checked;
  const writable = credentialWritesAllowed();
  const box = $("#s3-grant-list");
  box.classList.toggle("empty-state", buckets.length === 0);
  box.classList.toggle("disabled", !acl);
  box.innerHTML = buckets.length ? buckets.map((bucket) => {
    const current = grants?.[bucket.name] || {};
    return `<div class="grant-row"><strong>${escapeHtml(bucket.name)}</strong><label class="check-label compact"><input type="checkbox" data-s3-grant-read="${escapeHtml(bucket.name)}" ${current.read ? "checked" : ""} ${acl && writable ? "" : "disabled"}><span>读取</span></label><label class="check-label compact"><input type="checkbox" data-s3-grant-write="${escapeHtml(bucket.name)}" ${current.write ? "checked" : ""} ${acl && writable ? "" : "disabled"}><span>写入</span></label></div>`;
  }).join("") : "创建 R2 bucket 后可在这里分配读写权限。";
}

function renderS3Credentials(credentials) {
  const box = $("#s3-credential-list");
  box.classList.toggle("empty-state", credentials.length === 0);
  box.innerHTML = credentials.length ? credentials.map((item) => `<div class="database-row"><div><strong>${escapeHtml(item.label)}</strong><small><code>${escapeHtml(item.access_key_id)}</code> · ${item.active ? "有效" : "已撤销"}</small><div class="tag-row">${item.acl_enabled ? Object.entries(item.grants || {}).map(([bucket, grant]) => `<span class="badge">${escapeHtml(bucket)} ${grant.read ? "读" : ""}${grant.write ? "写" : ""}</span>`).join("") || '<span class="badge danger">默认拒绝</span>' : '<span class="badge active">全部 bucket 读写</span>'}</div><small>最近使用 ${escapeHtml(item.last_used_at_ms ? formatDate(item.last_used_at_ms) : "从未")}</small></div><div class="table-actions">${item.active ? `<button class="mini-button" type="button" data-s3-edit="${escapeHtml(item.id)}">权限</button><button class="mini-button danger" type="button" data-s3-revoke="${escapeHtml(item.id)}">撤销</button>` : '<span class="badge">不可用</span>'}</div></div>`).join("") : "暂无 S3 凭据。";
}

function formatDate(at) {
  const date = new Date(Number(at));
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString("zh-CN");
}

async function loadSecurity({ quiet = false } = {}) {
  try {
    state.security = await api("/api/security");
    renderSecurity();
    await loadSecurityAudit({ quiet: true });
    if (!quiet) toast("安全策略与凭据已刷新");
  } catch (error) {
    if (!quiet) toast(error.message, true);
  }
}

async function saveQuota(event) {
  event.preventDefault();
  const payload = {
    max_workers: Number($("#quota-workers").value),
    max_custom_hostnames: Number($("#quota-hostnames").value),
    max_worker_bytes: Number($("#quota-worker-bytes").value),
    max_requests_per_minute: Number($("#quota-requests").value),
    worker_outbound_allowed: $("#quota-outbound").checked,
    max_r2_local_bytes: Number($("#quota-r2-bytes").value),
    max_r2_objects: Number($("#quota-r2-objects").value),
  };
  try {
    const result = await api("/api/security/quota", { method: "PATCH", body: JSON.stringify(payload) });
    const complete = async () => { state.securityDirty = false; await loadSecurity({ quiet: true }); };
    if (result.pending_approval) showApproval(result, "更新集群资源、网络与请求配额。", complete);
    else await complete();
  } catch (error) { toast(error.message, true); }
}

function showCredential(title, value) {
  $("#credential-reveal-title").textContent = title;
  $("#credential-reveal-value").textContent = value;
  $("#credential-reveal").classList.remove("hidden");
  $("#credential-reveal").scrollIntoView({ behavior: "smooth", block: "center" });
}

async function createAccessToken(event) {
  event.preventDefault();
  const scopes = $$("#access-token-scopes input:checked").map((input) => input.value);
  if (!scopes.length) return toast("请至少选择一个作用域", true);
  if (scopes.includes("*") && scopes.length > 1) return toast("全部权限必须单独选择", true);
  const days = $("#access-token-days").value.trim();
  const payload = { label: $("#access-token-label").value.trim(), scopes, expires_in_days: days ? Number(days) : null };
  try {
    const result = await api("/api/security/tokens", { method: "POST", body: JSON.stringify(payload) });
    showCredential("新的 API 访问令牌", result.token);
    const complete = async () => { $("#access-token-form").reset(); await loadSecurity({ quiet: true }); };
    if (result.pending_approval) showApproval(result, "启用新 API 访问令牌；明文已在安全页面显示一次。", complete);
    else await complete();
  } catch (error) { toast(error.message, true); }
}

async function revokeAccessToken(id) {
  if (!window.confirm("撤销后使用此令牌的自动化会立即失去访问权限。继续吗？")) return;
  try {
    const result = await api(`/api/security/tokens/${encodeURIComponent(id)}`, { method: "DELETE" });
    const complete = () => loadSecurity({ quiet: true });
    if (result.pending_approval) showApproval(result, `撤销 API 访问令牌 ${id}。`, complete);
    else await complete();
  } catch (error) { toast(error.message, true); }
}

function collectS3Grants() {
  const grants = {};
  for (const bucket of state.r2Buckets || []) {
    const read = $(`[data-s3-grant-read="${CSS.escape(bucket.name)}"]`)?.checked || false;
    const write = $(`[data-s3-grant-write="${CSS.escape(bucket.name)}"]`)?.checked || false;
    if (read || write) grants[bucket.name] = { read, write };
  }
  return grants;
}

function resetS3CredentialForm() {
  state.s3Editing = null;
  $("#s3-credential-form").reset();
  $("#s3-acl-enabled").checked = true;
  $("#s3-credential-submit").textContent = "生成加密 S3 凭据";
  $("#s3-credential-cancel").classList.add("hidden");
  renderS3GrantList();
}

function editS3Credential(id) {
  const credential = state.security?.s3_credentials?.find((item) => item.id === id);
  if (!credential) return;
  state.s3Editing = id;
  $("#s3-credential-label").value = credential.label;
  $("#s3-acl-enabled").checked = credential.acl_enabled;
  $("#s3-credential-submit").textContent = "保存最小权限";
  $("#s3-credential-cancel").classList.remove("hidden");
  renderS3GrantList(credential.grants || {});
  $("#s3-credential-form").scrollIntoView({ behavior: "smooth" });
}

async function saveS3Credential(event) {
  event.preventDefault();
  const payload = { label: $("#s3-credential-label").value.trim(), acl_enabled: $("#s3-acl-enabled").checked, grants: collectS3Grants() };
  try {
    if (state.s3Editing) {
      const id = state.s3Editing;
      const result = await api(`/api/security/s3/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(payload) });
      const complete = async () => { resetS3CredentialForm(); await loadSecurity({ quiet: true }); };
      if (result.pending_approval) showApproval(result, `更新 S3 凭据 ${id} 的 bucket 权限。`, complete);
      else await complete();
      return;
    }
    const result = await api("/api/security/s3", { method: "POST", body: JSON.stringify(payload) });
    showCredential("新的 R2/S3 凭据", `Endpoint: ${location.origin}/s3\nAccess Key ID: ${result.access_key_id}\nSecret Access Key: ${result.secret_access_key}\nRegion: auto`);
    const complete = async () => { resetS3CredentialForm(); await loadSecurity({ quiet: true }); };
    if (result.pending_approval) showApproval(result, "启用新的加密 R2/S3 Signature V4 凭据。", complete);
    else await complete();
  } catch (error) { toast(error.message, true); }
}

async function revokeS3Credential(id) {
  if (!window.confirm("撤销后，使用此 Access Key 的 S3 客户端会立即失败。继续吗？")) return;
  try {
    const result = await api(`/api/security/s3/${encodeURIComponent(id)}`, { method: "DELETE" });
    const complete = () => loadSecurity({ quiet: true });
    if (result.pending_approval) showApproval(result, `撤销 R2/S3 凭据 ${id}。`, complete);
    else await complete();
  } catch (error) { toast(error.message, true); }
}

async function loadSecurityAudit({ quiet = false } = {}) {
  try {
    const data = await api("/api/security/audit?limit=500");
    state.auditRecords = data.records || [];
    const box = $("#security-audit-list");
    box.classList.toggle("empty-state", state.auditRecords.length === 0);
    box.innerHTML = state.auditRecords.length ? state.auditRecords.map((record) => `<article class="build-row success"><span class="pipeline-state success"></span><div><strong>${escapeHtml(record.kind)}/${escapeHtml(record.name)} · v${escapeHtml(record.version)}</strong><small>${record.deleted ? "墓碑" : record.redacted ? "敏感配置已隐藏" : "签名配置"}</small><code>${escapeHtml(record.digest)}</code></div><div><span class="badge">前序 ${escapeHtml(record.previous ? shortId(record.previous, 14) : "创世")}</span></div></article>`).join("") : "暂无平台资源历史。";
    if (!quiet) toast("签名资源审计已刷新");
  } catch (error) { if (!quiet) toast(error.message, true); }
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

function renderNodes() {
  const nodes = state.nodes;
  $("#node-nav-count").textContent = String(nodes.length);
  $("#nodes-live-count").textContent = `${nodes.filter((node) => node.live).length}/${nodes.length} 在线`;
  const list = $("#cluster-node-list");
  list.classList.toggle("empty-state", nodes.length === 0);
  list.innerHTML = nodes.length ? nodes.map((node) => {
    const tags = node.effective_tags || [];
    const deployments = Object.values(node.deployments || {});
    const running = deployments.filter((item) => ["ready", "running", "standby"].includes(item?.state)).length;
    const lifecycle = node.suspended ? "已停用" : node.drain ? "排空中" : node.live ? "可调度" : "离线";
    const dot = node.live ? (node.suspended ? "offline" : node.drain ? "pending" : "online") : "offline";
    return `<button class="node-row node-policy-row${state.nodeActive === node.id ? " selected" : ""}" type="button" data-cluster-node="${escapeHtml(node.id)}">
      <span class="dot ${dot}" title="${escapeHtml(lifecycle)}"></span>
      <div><div class="node-name">${escapeHtml(node.label || "未命名节点")}${node.local ? " · 当前节点" : ""}</div><div class="node-short">${escapeHtml(shortId(node.id, 18))} · ${escapeHtml(node.region || "未设区域")}</div><div class="tag-row">${tags.slice(0, 8).map((tag) => `<span class="badge">${escapeHtml(tag)}</span>`).join("") || '<span class="muted">无能力标签</span>'}</div></div>
      <div class="node-address">${running}/${deployments.length} 个实例</div><span class="badge${node.suspended ? " danger" : node.drain ? " pending" : " active"}">${escapeHtml(lifecycle)}</span>
    </button>`;
  }).join("") : "尚未发现集群节点。";
  if (state.nodeActive && !nodes.some((node) => node.id === state.nodeActive)) state.nodeActive = null;
  if (state.nodeActive && !state.nodePolicyDirty) selectNode(state.nodeActive, false);
}

function selectNode(id, rerender = true) {
  const node = state.nodes.find((item) => item.id === id);
  if (!node) return;
  if (state.nodeActive !== id) state.nodePolicyDirty = false;
  state.nodeActive = id;
  if (rerender) renderNodes();
  $("#node-policy-title").textContent = node.label || shortId(node.id, 18);
  $("#node-policy-summary").textContent = `${node.live ? "在线" : "离线"} · 策略 v${node.resource_version || "尚未创建"} · ${node.effective_tags?.length || 0} 个有效标签`;
  $("#node-policy-form").classList.remove("hidden");
  $("#node-policy-id").value = node.id;
  $("#node-policy-region").value = node.region || "";
  $("#node-policy-tags").value = (node.tags || []).join("\n");
  $("#node-policy-drain").checked = Boolean(node.drain);
  $("#node-policy-suspended").checked = Boolean(node.suspended);
  $("#node-policy-reason").value = node.reason || "";
}

async function loadNodes({ quiet = false } = {}) {
  try {
    const data = await api("/api/nodes");
    state.nodes = data.nodes || [];
    renderNodes();
    if (!quiet) toast("节点与调度策略已刷新");
  } catch (error) {
    $("#cluster-node-list").innerHTML = `<div class="empty-state">${escapeHtml(error.message)}</div>`;
    if (!quiet) toast(error.message, true);
  }
}

async function saveNodePolicy(event) {
  event.preventDefault();
  const id = state.nodeActive;
  if (!id) return;
  const payload = {
    region: $("#node-policy-region").value.trim(),
    tags: $("#node-policy-tags").value.split(/\s+/).map((tag) => tag.trim()).filter(Boolean),
    drain: $("#node-policy-drain").checked,
    suspended: $("#node-policy-suspended").checked,
    reason: $("#node-policy-reason").value.trim(),
  };
  try {
    const result = await api(`/api/nodes/${encodeURIComponent(id)}`, { method: "PATCH", body: JSON.stringify(payload) });
    const complete = async () => {
      state.nodePolicyDirty = false;
      await Promise.all([loadNodes({ quiet: true }), loadOverview({ quiet: true })]);
    };
    if (result.pending_approval) showApproval(result, `更新节点 ${shortId(id, 18)} 的签名调度策略。`, complete);
    else { toast(`节点策略 v${result.version} 已发布`); await complete(); }
  } catch (error) {
    toast(error.message, true);
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
    $("#credential-transport-warning").classList.toggle("hidden", credentialWritesAllowed());
    const credentialWritable = credentialWritesAllowed();
    $$("#access-token-form input, #access-token-form button, #s3-credential-form input, #s3-credential-form button")
      .forEach((control) => { control.disabled = !credentialWritable; });
    $("#security-copy").innerHTML = consoleMode === "public"
      ? "此节点不保存<br>任何私钥。"
      : "密钥仅保留在本地<br>控制台进程中。";
    $$("#deploy-form button, #source-form button, #kv-editor-form button, #d1-create-form button, #d1-exec-form button, #r2-bucket-form button, #r2-upload-form button, #r2-delete-bucket, #storage-form button, #storage-probe, #queue-form button, #queue-send-form button, #queue-delete, #analytics-form button, #analytics-write-form button, #analytics-delete, #pipeline-form button, #pipeline-token-form button, #pipeline-ingest-form button, #pipeline-flush, #pipeline-delete, #workflow-form button, #workflow-trigger-form button, #workflow-signal-form button, #workflow-delete, #flow-form button, #flow-token-form button, #flow-trigger-form button, #flow-delete, #network-rule-form button, #network-device-form button, #email-domain-form button, #email-route-form button, #email-send-form button, #email-delete, #email-verify, #binary-form button, #binary-new, #project-domain-add-form button, #project-bindings-form button, #project-secret-form button, #project-file-form button, #project-file-new, #project-triggers-form button, #project-cron-fire-form button, #project-cron-dlq button, #project-settings-form button, #project-preview-form button, #project-preview-list button, #project-source-form button, #project-redeploy, #project-delete, #quota-form button, #access-token-form button, #s3-credential-form button")
      .forEach((button) => { button.disabled = state.session.read_only; });
    $("#network-device-transport-warning").classList.toggle("hidden", consoleMode === "local" || credentialWritesAllowed());
    $("#node-policy-form button").disabled = state.session.read_only;
    $$("#access-token-form input, #access-token-form button, #s3-credential-form input, #s3-credential-form button")
      .forEach((control) => { control.disabled = !credentialWritable; });
    await loadOverview({ quiet: true });
    await loadNodes({ quiet: true });
    await loadWorkerOps();
    await loadKeys();
    await loadStorage({ quiet: true });
    await loadR2({ quiet: true });
    await loadQueues({ quiet: true });
    await loadAnalytics({ quiet: true });
    await loadPipelines({ quiet: true });
    await loadWorkflows({ quiet: true });
    await loadFlows({ quiet: true });
    await loadNetwork({ quiet: true });
    await loadEmail({ quiet: true });
    await loadBinaries({ quiet: true });
    await loadSecurity({ quiet: true });
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

$$(".nav-item").forEach((button) => button.addEventListener("click", () => {
  switchView(button.dataset.view);
  if (button.dataset.view === "nodes") loadNodes({ quiet: true });
  if (button.dataset.view === "storage") loadStorage({ quiet: true });
  if (button.dataset.view === "network") loadNetwork({ quiet: true });
  if (button.dataset.view === "binaries") loadBinaries({ quiet: true });
  if (button.dataset.view === "security") loadSecurity({ quiet: true });
}));
$$('[data-go]').forEach((button) => button.addEventListener("click", () => switchView(button.dataset.go)));
$("#overview-workers").addEventListener("click", (event) => {
  const button = event.target.closest("[data-open-worker]");
  if (button) openWorkerDetail(button.dataset.openWorker);
});
$("#cluster-node-list").addEventListener("click", (event) => {
  const button = event.target.closest("[data-cluster-node]");
  if (button) selectNode(button.dataset.clusterNode);
});
$("#node-policy-form").addEventListener("submit", saveNodePolicy);
$("#node-policy-form").addEventListener("input", () => { state.nodePolicyDirty = true; });
$("#node-policy-form").addEventListener("change", () => { state.nodePolicyDirty = true; });
$("#nodes-refresh").addEventListener("click", () => loadNodes());
$("#security-refresh").addEventListener("click", () => loadSecurity());
$("#security-audit-refresh").addEventListener("click", () => loadSecurityAudit());
$("#quota-form").addEventListener("submit", saveQuota);
$("#quota-form").addEventListener("input", () => { state.securityDirty = true; });
$("#quota-form").addEventListener("change", () => { state.securityDirty = true; });
$("#access-token-form").addEventListener("submit", createAccessToken);
$("#access-token-list").addEventListener("click", (event) => { const button = event.target.closest("[data-token-revoke]"); if (button) revokeAccessToken(button.dataset.tokenRevoke); });
$("#s3-credential-form").addEventListener("submit", saveS3Credential);
$("#s3-acl-enabled").addEventListener("change", () => {
  const editing = state.s3Editing ? state.security?.s3_credentials?.find((item) => item.id === state.s3Editing) : null;
  renderS3GrantList(editing?.grants || null);
});
$("#s3-credential-cancel").addEventListener("click", resetS3CredentialForm);
$("#s3-credential-list").addEventListener("click", (event) => {
  const edit = event.target.closest("[data-s3-edit]");
  const revoke = event.target.closest("[data-s3-revoke]");
  if (edit) editS3Credential(edit.dataset.s3Edit);
  if (revoke) revokeS3Credential(revoke.dataset.s3Revoke);
});
$("#credential-reveal-copy").addEventListener("click", () => copyText($("#credential-reveal-value").textContent, $("#credential-reveal-copy")));
$("#credential-reveal-close").addEventListener("click", () => { $("#credential-reveal-value").textContent = ""; $("#credential-reveal").classList.add("hidden"); });
$("#new-project").addEventListener("click", () => {
  state.activeWorker = null;
  state.workerDetail = null;
  state.workerFile = null;
  switchView("worker-new");
  window.scrollTo({ top: 0, behavior: "smooth" });
  setTimeout(() => $("#source-worker").focus(), 300);
});
$("#new-project-back").addEventListener("click", () => switchView("workers"));
$("#project-back").addEventListener("click", () => {
  state.activeWorker = null;
  state.workerDetail = null;
  state.workerFile = null;
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
$("#project-secret-form").addEventListener("submit", saveWorkerSecret);
$("#project-file-form").addEventListener("submit", saveWorkerFile);
$("#project-file-new").addEventListener("click", newWorkerFile);
$("#project-file-delete").addEventListener("click", deleteWorkerFile);
$("#project-file-type").addEventListener("change", () => {
  const module = $("#project-file-type").value === "module";
  $("#project-file-main").disabled = !module;
  if (!module) $("#project-file-main").checked = false;
});
$("#project-triggers-form").addEventListener("submit", saveProjectTriggers);
$("#project-cron-fire-form").addEventListener("submit", fireProjectCron);
$("#project-cron-refresh").addEventListener("click", () => loadCronRuns());
$("#project-cron-dlq").addEventListener("click", (event) => {
  const replay = event.target.closest("button[data-cron-replay]");
  const remove = event.target.closest("button[data-cron-delete]");
  if (replay) replayProjectCron(replay.dataset.cronReplay);
  if (remove) deleteProjectCronDlq(remove.dataset.cronDelete);
});
$("#project-settings-form").addEventListener("submit", saveProjectSettings);
$("#project-preview-form").addEventListener("submit", createWorkerPreview);
$("#project-preview-refresh").addEventListener("click", () => loadWorkerPreviews({ quiet: false }));
$("#project-preview-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-preview-delete]");
  if (button) deleteWorkerPreview(button.dataset.previewDelete);
});
$("#project-source-form").addEventListener("submit", saveProjectSource);
$("#project-source-webhook").addEventListener("change", () => {
  $("#project-source-pr-previews").disabled = !$("#project-source-webhook").checked;
});
$("#project-source-disconnect").addEventListener("click", () => state.activeWorker && disconnectSource(state.activeWorker));
$("#project-delete").addEventListener("click", () => state.activeWorker && deleteWorker(state.activeWorker));
$("#detail-refresh-logs").addEventListener("click", loadDetailLogs);
$("#detail-refresh-requests").addEventListener("click", loadRequestLogs);
$("#request-log-filter").addEventListener("submit", (event) => {
  event.preventDefault();
  loadRequestLogs();
});
$("#refresh").addEventListener("click", async () => {
  await loadOverview();
  await loadNodes({ quiet: true });
  await loadStorage({ quiet: true });
  await loadR2({ quiet: true });
  await loadQueues({ quiet: true });
  await loadAnalytics({ quiet: true });
  await loadPipelines({ quiet: true });
  await loadWorkflows({ quiet: true });
  await loadFlows({ quiet: true });
  await loadNetwork({ quiet: true });
  await loadEmail({ quiet: true });
  await loadBinaries({ quiet: true });
});
$("#deploy-form").addEventListener("submit", deployWorker);
$("#deploy-file-picker").addEventListener("click", () => $("#deploy-files").click());
$("#deploy-files").addEventListener("change", updateDeployFileStatus);
$("#source-form").addEventListener("submit", connectSource);
$("#source-webhook").addEventListener("change", () => {
  $("#source-pr-previews").disabled = !$("#source-webhook").checked;
});
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
$("#storage-form").addEventListener("submit", saveStorage);
$("#storage-probe").addEventListener("click", probeStorage);
$("#storage-refresh").addEventListener("click", () => loadStorage());
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
$("#flow-form").addEventListener("submit", saveFlow);
$("#flow-trigger").addEventListener("change", updateFlowTriggerFields);
$("#flow-new").addEventListener("click", newFlow);
$("#flow-delete").addEventListener("click", deleteFlow);
$("#flow-node-form").addEventListener("submit", saveFlowNode);
$("#flow-node-remove").addEventListener("click", removeFlowNode);
$("#flow-edge-form").addEventListener("submit", addFlowEdge);
$("#flow-graph-apply").addEventListener("click", applyFlowGraphJson);
$("#flow-graph-copy").addEventListener("click", () => copyText($("#flow-graph-json").value, $("#flow-graph-copy")));
$("#flow-token-form").addEventListener("submit", mintFlowToken);
$("#flow-copy-token").addEventListener("click", () => copyText($("#flow-new-token").textContent, $("#flow-copy-token")));
$("#flow-trigger-form").addEventListener("submit", triggerFlow);
$("#flow-refresh").addEventListener("click", loadFlowRuns);
$("#flow-palette").addEventListener("click", (event) => { const button = event.target.closest("[data-flow-add]"); if (button) addFlowNode(button.dataset.flowAdd); });
$("#flow-canvas").addEventListener("pointerdown", startFlowDrag);
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
$("#project-secret-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-delete-secret]");
  if (button) deleteWorkerSecret(button.dataset.deleteSecret);
});
$("#project-file-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-worker-file]");
  if (button) openWorkerFile(button.dataset.workerFile);
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
$("#flow-list").addEventListener("click", (event) => { const button = event.target.closest("[data-flow]"); if (button) selectFlow(button.dataset.flow); });
$("#flow-edge-list").addEventListener("click", (event) => { const button = event.target.closest("[data-flow-edge-remove]"); if (!button) return; state.flowGraph.edges = state.flowGraph.edges.filter((edge) => edge.id !== button.dataset.flowEdgeRemove); renderFlowCanvas(); });
$("#flow-token-list").addEventListener("click", (event) => { const button = event.target.closest("[data-flow-token-revoke]"); if (button) revokeFlowToken(button.dataset.flowTokenRevoke); });
$("#flow-runs").addEventListener("click", (event) => { const button = event.target.closest("[data-flow-run]"); if (button) openFlowRun(button.dataset.flowRun); });
$("#flow-run-actions").addEventListener("click", (event) => { const button = event.target.closest("[data-flow-action]"); if (button) runFlowAction(button.dataset.flowAction); });
$("#network-refresh").addEventListener("click", () => loadNetwork());
$("#network-rule-new").addEventListener("click", resetNetworkRuleForm);
$("#network-rule-form").addEventListener("submit", saveNetworkRule);
$("#network-rule-delete").addEventListener("click", deleteNetworkRule);
$("#network-rule-list").addEventListener("click", (event) => { const button = event.target.closest("[data-network-rule]"); if (button) selectNetworkRule(button.dataset.networkRule); });
$("#network-device-new").addEventListener("click", resetNetworkDeviceForm);
$("#network-device-form").addEventListener("submit", saveNetworkDevice);
$("#network-device-revoke").addEventListener("click", revokeNetworkDevice);
$("#network-device-delete").addEventListener("click", deleteNetworkDevice);
$("#network-device-list").addEventListener("click", (event) => { const button = event.target.closest("[data-network-device]"); if (button) selectNetworkDevice(button.dataset.networkDevice); });
$("#network-token-copy").addEventListener("click", () => copyText($("#network-token-value").textContent, $("#network-token-copy")));
$("#email-domain-form").addEventListener("submit", saveEmailDomain);
$("#email-route-form").addEventListener("submit", saveEmailRoute);
$("#email-route-match").addEventListener("change", updateEmailRouteFields);
$("#email-route-destination").addEventListener("change", updateEmailRouteFields);
$("#email-verify").addEventListener("click", verifyEmailDomain);
$("#email-delete").addEventListener("click", deleteEmailDomain);
$("#email-new").addEventListener("click", resetEmailDomainForm);
$("#email-refresh").addEventListener("click", loadEmailMessages);
$("#email-send-form").addEventListener("submit", sendEmailMessage);
$("#email-domain-list").addEventListener("click", (event) => { const button = event.target.closest("[data-email-domain]"); if (button) selectEmailDomain(button.dataset.emailDomain); });
$("#email-route-list").addEventListener("click", (event) => {
  const edit = event.target.closest("[data-email-route-edit]");
  const remove = event.target.closest("[data-email-route-remove]");
  if (edit) fillEmailRouteForm(state.emailRoutes.find((route) => route.id === edit.dataset.emailRouteEdit));
  if (remove) { state.emailRoutes = state.emailRoutes.filter((route) => route.id !== remove.dataset.emailRouteRemove); renderEmailRoutes(); }
});
$("#email-message-list").addEventListener("click", (event) => { const button = event.target.closest("[data-email-message]"); if (button) openEmailMessage(button.dataset.emailMessage); });
$("#binary-new").addEventListener("click", () => { resetBinaryForm(); $("#binary-name").focus(); });
$("#binary-form").addEventListener("submit", saveBinary);
$("#binary-delete").addEventListener("click", deleteBinary);
$("#binary-storage-backend").addEventListener("change", toggleBinaryStorageFields);
$("#binary-list").addEventListener("click", (event) => { const button = event.target.closest("[data-binary]"); if (button) selectBinary(button.dataset.binary); });
updateEmailRouteFields();
toggleBinaryStorageFields();
resetNetworkRuleForm();
resetNetworkDeviceForm();

setInterval(() => {
  if (state.session) {
    loadOverview({ quiet: true });
    loadWorkerOps();
    if (state.view === "nodes") loadNodes({ quiet: true });
    if (state.view === "r2") loadR2({ quiet: true });
    if (state.view === "storage") loadStorage({ quiet: true });
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
    if (state.view === "flows") loadFlows({ quiet: true }).then(() => {
      if (state.flowActive) selectFlow(state.flowActive);
    });
    if (state.view === "network") loadNetwork({ quiet: true });
    if (state.view === "email") loadEmail({ quiet: true }).then(() => {
      if (state.emailActive) loadEmailMessages();
    });
    if (state.view === "binaries") loadBinaries({ quiet: true });
    if (state.view === "security") loadSecurity({ quiet: true });
  }
}, 10_000);
boot();
