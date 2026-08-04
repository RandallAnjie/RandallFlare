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
  sources: [],
  builds: [],
  buildTimer: null,
  activeLog: null,
};

const titles = {
  overview: ["CLUSTER CONTROL", "Overview"],
  workers: ["SIGNED MANIFESTS", "Workers"],
  kv: ["DISTRIBUTED DATA", "KV Store"],
  d1: ["REPLICATED SQLITE", "D1 Databases"],
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
      const error = new Error(payload?.error || payload || `Request failed (${response.status})`);
      error.status = response.status;
      throw error;
    }
    return payload;
  } finally {
    setBusy(false);
  }
}

function authorizationCommand(code, node) {
  return `RF_NODE=${node} RF_CLUSTER_SECRET='YOUR_64_HEX_CLUSTER_SECRET' RF_OPERATOR_KEY=~/.rf/operator.key rf authorize ${code}`;
}

async function copyText(text, button) {
  try {
    await navigator.clipboard.writeText(text);
    const previous = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => { button.textContent = previous; }, 1200);
  } catch {
    toast("Copy failed; select the command manually", true);
  }
}

async function beginAuthorization() {
  clearTimeout(state.authTimer);
  state.authChallenge = null;
  document.body.classList.add("auth-required");
  $("#auth-gate").classList.remove("hidden");
  $("#auth-retry").classList.add("hidden");
  $("#auth-dot").className = "dot pending";
  $("#auth-status").textContent = "Creating signed challenge";
  $("#auth-code").textContent = "Generating…";
  try {
    const response = await fetch("/api/auth/challenge", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Challenge failed (${response.status})`);
    state.authChallenge = data;
    const command = authorizationCommand(data.code, data.approve_node);
    $("#auth-code").textContent = data.code;
    $("#auth-command").textContent = command;
    $("#auth-status").textContent = "Waiting for operator signature";
    state.authTimer = setTimeout(pollAuthorization, 900);
  } catch (error) {
    $("#auth-dot").className = "dot offline";
    $("#auth-status").textContent = error.message;
    $("#auth-retry").classList.remove("hidden");
  }
}

async function pollAuthorization() {
  const challenge = state.authChallenge;
  if (!challenge) return;
  try {
    const response = await fetch(`/api/auth/challenge/${encodeURIComponent(challenge.id)}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || `Authorization failed (${response.status})`);
    if (data.state === "completed") {
      $("#auth-dot").className = "dot online";
      $("#auth-status").textContent = "Operator verified";
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
  $$(".nav-item").forEach((item) => item.classList.toggle("active", item.dataset.view === view));
  $$(".view").forEach((item) => item.classList.toggle("active", item.id === `view-${view}`));
  $("#section-eyebrow").textContent = titles[view][0];
  $("#section-title").textContent = titles[view][1];
}

function renderOverview(data) {
  state.overview = data;
  const peers = Array.isArray(data.peers) ? data.peers : [];
  const workers = Array.isArray(data.workers) ? data.workers : [];
  const databases = Array.isArray(data.databases) ? data.databases : [];
  const allNodes = [
    {
      id: data.node,
      label: data.label || "local node",
      public: Boolean(data.public),
      api: data.console?.connected_to || "—",
      local: true,
    },
    ...peers,
  ];

  $("#metric-nodes").textContent = String(allNodes.length);
  $("#metric-public").textContent = `${allNodes.filter((node) => node.public).length} public`;
  $("#metric-workers").textContent = String(workers.length);
  const routeCount = workers.reduce((total, worker) => total + (worker.hostnames?.length || 0), 0);
  $("#metric-routes").textContent = `${routeCount} hostname route${routeCount === 1 ? "" : "s"}`;
  $("#metric-databases").textContent = String(databases.length);
  $("#metric-blobs").textContent = String(data.missing_blobs ?? 0);
  $("#cluster-version").textContent = `rf ${data.version || "—"}`;
  $("#node-label").textContent = data.label || "Unnamed node";
  $("#node-id").textContent = data.node || "—";
  $("#node-api").textContent = data.console?.connected_to || "—";
  $("#operator-id").textContent = data.console?.operator || "Not configured";
  $("#manifest-digest").textContent = data.manifest_digest || "Not reported";
  $("#console-mode").textContent = data.console?.read_only ? "Read-only" : "Operator";
  $("#worker-nav-count").textContent = String(workers.length);
  $("#worker-count").textContent = `${workers.length} live`;

  $("#node-list").classList.remove("empty-state");
  $("#node-list").innerHTML = allNodes
    .map((node) => `
      <div class="node-row">
        <span class="dot online" title="Live"></span>
        <div><div class="node-name">${escapeHtml(node.label || "unnamed")}${node.local ? " · this node" : ""}</div><div class="node-short">${escapeHtml(shortId(node.id))}</div></div>
        <div class="node-address">${escapeHtml(node.api || node.ip4 || "address unavailable")}</div>
        <span class="badge">${node.public ? "public" : "inner"}</span>
      </div>`)
    .join("");

  const strip = $("#overview-workers");
  strip.classList.toggle("empty-state", workers.length === 0);
  strip.innerHTML = workers.length
    ? workers.slice(0, 6).map((worker) => `
      <div class="worker-card">
        <strong>${escapeHtml(worker.name)} <span class="badge">v${escapeHtml(worker.version)}</span></strong>
        <p>${escapeHtml(worker.hostnames?.join(", ") || "No hostname")}</p>
      </div>`).join("")
    : "No active workers.";

  renderWorkers(workers);
  renderDatabases(databases);
  renderNamespaces(Array.isArray(data.kv_namespaces) ? data.kv_namespaces : []);
  $("#connection-dot").className = "dot online";
  $("#connection-text").textContent = `Connected · ${data.label || "node"}`;
  showError();
}

function renderWorkers(workers) {
  const table = $("#workers-table");
  const mutationDisabled = state.session?.read_only
    ? ' disabled title="Load an operator key to change Workers"'
    : "";
  table.innerHTML = workers.length
    ? workers.map((worker) => {
      const content = worker.modules
        ? `${worker.modules} module${worker.modules === 1 ? "" : "s"} · ${worker.assets || 0} assets`
        : `${worker.assets || 0} asset${worker.assets === 1 ? "" : "s"}`;
      const distribution = worker.distribution || { ready: 0, total: 1, nodes: [] };
      const complete = distribution.ready === distribution.total;
      const nodeStates = (distribution.nodes || []).map((node) => {
        const status = node.status || {};
        return `${node.label || shortId(node.node)}: ${status.state || "unknown"} v${status.version || "—"}`;
      }).join("\n");
      return `<tr>
        <td><strong>${escapeHtml(worker.name)}</strong><small>${worker.crons?.length || 0} cron trigger${worker.crons?.length === 1 ? "" : "s"}</small></td>
        <td class="mono">v${escapeHtml(worker.version)}</td>
        <td>${escapeHtml(content)}</td>
        <td><small>${escapeHtml(worker.hostnames?.join(", ") || "—")}</small></td>
        <td><span class="${complete ? "state-ok" : "state-wait"}" title="${escapeHtml(nodeStates)}">${escapeHtml(distribution.ready)}/${escapeHtml(distribution.total)} nodes</span><small>${complete ? "fully distributed" : "converging"}</small></td>
        <td><div class="table-actions"><button class="mini-button" data-action="runtime" data-worker="${escapeHtml(worker.name)}">Runtime log</button><button class="mini-button" data-action="history" data-worker="${escapeHtml(worker.name)}">History</button><button class="mini-button danger" data-action="delete-worker" data-worker="${escapeHtml(worker.name)}"${mutationDisabled}>Delete</button></div></td>
      </tr>`;
    }).join("")
    : '<tr><td colspan="6" class="empty-state">No workers found.</td></tr>';
}

function buildStateLabel(stateName) {
  return {
    queued: "Queued",
    cloning: "Cloning",
    building: "Building",
    packaging: "Packaging",
    awaiting_approval: "Awaiting signature",
    deployed: "Deployed",
    failed: "Failed",
  }[stateName] || stateName || "Unknown";
}

function renderSources(data) {
  state.sources = data.sources || [];
  const capabilities = data.capabilities || {};
  const cap = $("#build-capabilities");
  const gitReady = Boolean(capabilities.git);
  const sandboxReady = Boolean(capabilities.sandbox);
  cap.innerHTML = `<span class="dot ${gitReady ? "online" : "offline"}"></span><strong>${gitReady ? "Build host ready" : "Git unavailable"}</strong><span>git ${gitReady ? "✓" : "×"}</span><span>bwrap ${sandboxReady ? "✓" : "optional"}</span><span>private token ${capabilities.github_token_configured ? "✓" : "not set"}</span>`;
  $("#source-count").textContent = `${state.sources.length} connected`;
  const list = $("#source-list");
  list.classList.toggle("empty-state", state.sources.length === 0);
  list.innerHTML = state.sources.length ? state.sources.map((source) => `
    <article class="source-card">
      <div class="source-icon">GH</div>
      <div class="source-main">
        <div class="source-title"><strong>${escapeHtml(source.worker)}</strong><span class="badge">source v${escapeHtml(source.version)}</span>${source.webhook ? '<span class="badge active">push enabled</span>' : ""}</div>
        <a href="${escapeHtml(source.repository.replace(/\.git$/, ""))}" target="_blank" rel="noreferrer">${escapeHtml(source.repository.replace(/\.git$/, ""))}</a>
        <div class="source-meta"><span>branch <code>${escapeHtml(source.branch)}</code></span><span>root <code>${escapeHtml(source.root)}</code></span><span>output <code>${escapeHtml(source.output_dir)}</code></span><span>${source.build_command ? "sandboxed build" : "zero-config"}</span></div>
        ${source.webhook ? `<details><summary>GitHub webhook setup</summary><div class="webhook-grid"><span>Payload URL</span><code>${escapeHtml(`${location.origin}${source.webhook_path}`)}</code><span>Secret</span><code>${escapeHtml(source.webhook_secret || "unavailable")}</code><span>Events</span><code>Just the push event</code></div></details>` : ""}
      </div>
      <div class="source-actions"><button class="primary" data-source-action="build" data-worker="${escapeHtml(source.worker)}">Build now</button><button class="mini-button" data-source-action="edit" data-worker="${escapeHtml(source.worker)}">Edit</button><button class="mini-button danger" data-source-action="disconnect" data-worker="${escapeHtml(source.worker)}">Disconnect</button></div>
    </article>`).join("") : "No GitHub repositories connected. Connect one above to enable builds and push deployments.";
}

function renderBuilds(jobs, approveNode) {
  state.builds = jobs || [];
  const list = $("#build-list");
  list.classList.toggle("empty-state", state.builds.length === 0);
  list.innerHTML = state.builds.length ? state.builds.map((job) => {
    const terminal = job.state === "deployed" || job.state === "failed";
    const short = job.commit ? job.commit.slice(0, 12) : "pending";
    const approval = job.approval && job.state === "awaiting_approval"
      ? `<button class="primary" data-build-action="approve" data-build="${escapeHtml(job.id)}" data-node="${escapeHtml(job.approve_node || approveNode || "")}">Sign release</button>` : "";
    return `<article class="build-row ${job.state === "failed" ? "failed" : ""}">
      <span class="pipeline-state ${terminal ? job.state : "active"}"></span>
      <div><strong>${escapeHtml(job.worker)}</strong><small>${escapeHtml(job.trigger)} · ${escapeHtml(job.branch)} · <code>${escapeHtml(short)}</code></small></div>
      <div class="build-stage"><span class="badge ${job.state === "deployed" ? "active" : ""}">${escapeHtml(buildStateLabel(job.state))}</span><small>${job.version ? `release v${escapeHtml(job.version)}` : "artifact pending"}</small></div>
      <div class="table-actions">${approval}<button class="mini-button" data-build-action="log" data-build="${escapeHtml(job.id)}">View log</button></div>
    </article>`;
  }).join("") : "No builds yet. Connect a repository and start the first build.";
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
    showApproval(result, `Connect ${payload.worker} to GitHub.`);
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
  if (!window.confirm(`Disconnect GitHub from “${worker}”? Deployed releases keep running.`)) return;
  try {
    const result = await api(`/api/sources/${encodeURIComponent(worker)}`, { method: "DELETE" });
    showApproval(result, `Disconnect the repository from ${worker}.`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function triggerBuild(worker) {
  try {
    const result = await api(`/api/workers/${encodeURIComponent(worker)}/build`, { method: "POST", body: "{}" });
    toast(`Build queued for ${worker}`);
    await loadWorkerOps();
    openBuildLog(result.job.id);
  } catch (error) {
    toast(error.message, true);
  }
}

async function openBuildLog(id) {
  clearTimeout(state.buildTimer);
  state.activeLog = { type: "build", id };
  $("#log-eyebrow").textContent = "LIVE BUILD LOG";
  $("#log-title").textContent = "Build activity";
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
    $("#log-content").textContent = (job.log || []).join("\n") || "Waiting for build output…";
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
  }, `Deploy the immutable artifact built for ${job.worker}.`);
}

async function openRuntimeLog(worker) {
  clearTimeout(state.buildTimer);
  state.activeLog = { type: "runtime", worker };
  $("#log-eyebrow").textContent = "LOCAL RUNTIME LOG";
  $("#log-title").textContent = worker;
  $("#log-dialog").showModal();
  try {
    const data = await api(`/api/workers/${encodeURIComponent(worker)}/runtime-log?limit=500`);
    $("#log-meta").textContent = `Node ${shortId(data.node, 20)} · bounded in-memory log`;
    $("#log-content").textContent = (data.lines || []).map((line) => `${new Date(line.at_ms).toISOString()} [v${line.version}] [${line.stream}] ${line.message}`).join("\n") || "No runtime output captured on this node.";
    $("#log-content").scrollTop = $("#log-content").scrollHeight;
  } catch (error) {
    $("#log-content").textContent = error.message;
  }
}

function renderDatabases(databases) {
  const list = $("#database-list");
  list.classList.toggle("empty-state", databases.length === 0);
  list.innerHTML = databases.length
    ? databases.map((name) => `<button class="database-button" type="button" data-database="${escapeHtml(name)}"><span>${escapeHtml(name)}</span><span>query →</span></button>`).join("")
    : "No databases reported.";
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
    if (!quiet) toast("Cluster state refreshed");
  } catch (error) {
    if (consoleMode === "public" && error.status === 401) {
      state.session = null;
      showError("");
      if (!state.authChallenge) await beginAuthorization();
      return;
    }
    $("#connection-dot").className = "dot offline";
    $("#connection-text").textContent = "Disconnected";
    showError(error.message);
    if (!quiet) toast(error.message, true);
  }
}

async function loadHistory(name) {
  try {
    const data = await api(`/api/workers/${encodeURIComponent(name)}/log`);
    $("#history-title").textContent = `${name} history`;
    $("#history-content").innerHTML = `
      <p class="muted"><span class="state-ok">✓ Hash chain verified</span> · signer ${escapeHtml(shortId(data.signer, 24))}</p>
      ${data.entries.slice().reverse().map((entry, index) => `<div class="history-entry"><div class="version">v${escapeHtml(entry.version)}${entry.deleted ? " · deleted" : ""}</div><div>${escapeHtml(entry.hostnames?.join(", ") || "No routes")}<code>${escapeHtml(entry.digest)}</code></div>${!entry.deleted && index > 0 ? `<button class="mini-button" data-rollback-worker="${escapeHtml(name)}" data-rollback-version="${escapeHtml(entry.version)}">Rollback</button>` : ""}</div>`).join("") || '<p class="empty-state">No log entries.</p>'}`;
    $("#history-dialog").showModal();
  } catch (error) {
    toast(error.message, true);
  }
}

async function rollbackWorker(worker, version) {
  if (!window.confirm(`Deploy the content of ${worker} v${version} as a new signed version?`)) return;
  try {
    const result = await api(`/api/workers/${encodeURIComponent(worker)}/rollback/${encodeURIComponent(version)}`, { method: "POST", body: "{}" });
    $("#history-dialog").close();
    showApproval(result, `Rollback ${worker} to v${version}.`);
  } catch (error) {
    toast(error.message, true);
  }
}

async function deleteWorker(name) {
  if (!window.confirm(`Tombstone Worker “${name}”? Existing history remains verifiable.`)) return;
  try {
    const result = await api(`/api/workers/${encodeURIComponent(name)}`, { method: "DELETE" });
    if (result.pending_approval) {
      showApproval(result, `${name} will be tombstoned after operator approval.`);
    } else {
      toast(`${name} tombstoned at v${result.version}`);
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

async function browserBundleFiles() {
  const selected = Array.from($("#deploy-files").files || []);
  if (!selected.length) throw new Error("Select a Worker bundle directory");
  const rawPaths = selected.map((file) => file.webkitRelativePath || file.name);
  const firstRoot = rawPaths[0].split("/")[0];
  const stripRoot = rawPaths.every((path) => path.startsWith(`${firstRoot}/`));
  const files = [];
  let total = 0;
  for (let index = 0; index < selected.length; index += 1) {
    const file = selected[index];
    const bytes = new Uint8Array(await file.arrayBuffer());
    total += bytes.length;
    if (total > 64 * 1024 * 1024) throw new Error("Worker bundle exceeds 64 MiB");
    const raw = rawPaths[index];
    const path = stripRoot ? raw.slice(firstRoot.length + 1) : raw;
    files.push({ path, data_base64: bytesToBase64(bytes) });
  }
  return files;
}

function showApproval(result, fallbackSummary) {
  clearTimeout(state.approvalTimer);
  const approval = result.approval;
  const command = authorizationCommand(approval.code, result.approve_node);
  $("#approval-title").textContent = result.name
    ? `${result.name} v${result.version}`
    : "Approve cluster change";
  $("#approval-summary").textContent = approval.summary || fallbackSummary;
  $("#approval-code").textContent = approval.code;
  $("#approval-command").textContent = command;
  $("#approval-dot").className = "dot pending";
  $("#approval-status").textContent = "Waiting for operator signature";
  $("#approval-dialog").showModal();
  state.approvalTimer = setTimeout(() => pollApproval(approval.id), 900);
}

async function pollApproval(id) {
  try {
    const result = await api(`/api/approvals/${encodeURIComponent(id)}`);
    if (result.state === "completed") {
      $("#approval-dot").className = "dot online";
      $("#approval-status").textContent = "Signed and committed across the cluster";
      toast(result.summary || "Cluster change committed");
      await loadOverview({ quiet: true });
      await loadWorkerOps();
      return;
    }
    if (result.state === "failed") {
      throw new Error(result.error || "Cluster change failed");
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
    $("#kv-count").textContent = `${data.keys.length} key${data.keys.length === 1 ? "" : "s"}`;
    const list = $("#kv-keys");
    list.classList.toggle("empty-state", data.keys.length === 0);
    list.innerHTML = data.keys.length
      ? data.keys.map((key) => `<button class="key-button" type="button" data-key="${escapeHtml(key)}"><span>${escapeHtml(key)}</span><span>edit →</span></button>`).join("")
      : "No keys match this prefix.";
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
    $("#kv-value").value = data.text ?? `[binary value; base64]\n${data.base64}`;
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
  $("#kv-editor-title").textContent = "New key";
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
    toast(`Saved ${payload.namespace}/${payload.key}`);
    await loadKeys();
  } catch (error) {
    toast(error.message, true);
  }
}

async function removeKey() {
  const namespace = $("#kv-namespace").value.trim();
  const key = $("#kv-key").value;
  if (!key || !window.confirm(`Delete ${namespace}/${key}?`)) return;
  try {
    const query = new URLSearchParams({ namespace, key });
    await api(`/api/kv/value?${query}`, { method: "DELETE" });
    toast(`Deleted ${namespace}/${key}`);
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
      showApproval(result, `${result.name} v${result.version} is ready for signing.`);
    } else {
      toast(`Deployed ${result.name} v${result.version}`);
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
    toast(`Created D1 database ${name}`);
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
    toast("D1 parameters must be valid JSON", true);
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
    toast("SQL executed successfully");
  } catch (error) {
    $("#d1-result").textContent = error.message;
    $("#d1-result-meta").textContent = "failed";
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
    $("#deploy-files").required = consoleMode === "public";
    $("#git-workspace").classList.toggle("hidden", consoleMode !== "public");
    $("#deploy-mode").textContent = state.session.read_only
      ? "No operator key loaded. All mutations are disabled."
      : consoleMode === "public"
        ? `Authenticated as ${shortId(state.session.operator, 22)}. Worker manifests require one-time CLI approval.`
        : `Signing as ${shortId(state.session.operator, 22)}.`;
    $("#transport-warning").classList.toggle(
      "hidden",
      consoleMode !== "public" || state.session.secure_transport,
    );
    $("#security-copy").innerHTML = consoleMode === "public"
      ? "No private key is stored<br>on this node."
      : "Secrets remain in the local<br>console process.";
    $$("#deploy-form button, #source-form button, #kv-editor-form button, #d1-create-form button, #d1-exec-form button")
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
$("#refresh").addEventListener("click", () => loadOverview());
$("#deploy-form").addEventListener("submit", deployWorker);
$("#source-form").addEventListener("submit", connectSource);
$("#build-refresh").addEventListener("click", () => loadWorkerOps({ quiet: false }));
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
  if (button.dataset.action === "history") loadHistory(button.dataset.worker);
  if (button.dataset.action === "runtime") openRuntimeLog(button.dataset.worker);
  if (button.dataset.action === "delete-worker") deleteWorker(button.dataset.worker);
});
$("#source-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-source-action]");
  if (!button) return;
  if (button.dataset.sourceAction === "build") triggerBuild(button.dataset.worker);
  if (button.dataset.sourceAction === "edit") editSource(button.dataset.worker);
  if (button.dataset.sourceAction === "disconnect") disconnectSource(button.dataset.worker);
});
$("#build-list").addEventListener("click", (event) => {
  const button = event.target.closest("button[data-build-action]");
  if (!button) return;
  if (button.dataset.buildAction === "log") openBuildLog(button.dataset.build);
  if (button.dataset.buildAction === "approve") approveBuild(button.dataset.build, button.dataset.node);
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
