const state = {
  summary: null,
  servers: [],
  deployments: [],
  subscriptions: [],
  chains: [],
  clients: [],
  chainDraft: [],
  chainProtocolDraft: {},
  activeJobId: null,
  jobTimer: null,
};

const CHAIN_PROTOCOL_VLESS_REALITY = "vless_reality";
const CHAIN_PROTOCOL_SHADOWSOCKS_2022 = "shadowsocks_2022";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function csrfToken() {
  const cookies = document.cookie.split(";").map((item) => item.trim());
  const entry = cookies.find((item) =>
    item.startsWith("myn_csrf=") || item.startsWith("__Host-myn_csrf="),
  );
  return entry ? decodeURIComponent(entry.split("=", 2)[1]) : "";
}

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  const method = String(options.method || "GET").toUpperCase();
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    headers["X-CSRF-Token"] = csrfToken();
  }
  const response = await fetch(path, {
    credentials: "same-origin",
    ...options,
    headers,
  });
  const data = await response.json().catch(() => ({}));
  if (response.status === 401) {
    window.location.href = `/login?next=${encodeURIComponent(window.location.pathname)}`;
    throw new Error(data.error || "登录已过期");
  }
  if (!response.ok) {
    throw new Error(data.error || "请求失败");
  }
  return data;
}

async function logout() {
  await api("/api/auth/logout", {
    method: "POST",
    body: "{}",
  });
  window.location.href = "/login";
}

function formData(form) {
  const data = Object.fromEntries(new FormData(form).entries());
  for (const input of form.querySelectorAll('input[type="checkbox"]')) {
    data[input.name] = input.checked;
  }
  return data;
}

function toast(message) {
  const node = $("#toast");
  node.textContent = message;
  node.hidden = false;
  clearTimeout(node.timer);
  node.timer = setTimeout(() => {
    node.hidden = true;
  }, 2800);
}

function setSection(id) {
  const meta = {
    overview: ["CONTROL CENTER", "总览"],
    subscriptions: ["DISTRIBUTION", "订阅"],
    servers: ["INFRASTRUCTURE", "服务器"],
    deployments: ["PROVISIONING", "部署"],
    chains: ["ROUTING", "代理链"],
    clients: ["ACCESS", "客户端"],
    logs: ["ACTIVITY", "任务日志"],
  };
  $$(".section").forEach((section) => {
    section.classList.toggle("is-active", section.id === id);
  });
  $$(".nav-item").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.section === id);
  });
  const [eyebrow, title] = meta[id] || meta.overview;
  $("#pageEyebrow").textContent = eyebrow;
  $("#pageTitle").textContent = title;
  $("#topAddServerBtn").hidden = id !== "servers";
}

function statusBadge(status) {
  const map = {
    ready: "ok",
    reachable: "ok",
    enabled: "ok",
    success: "ok",
    deploying: "warn",
    provisioning: "warn",
    running: "warn",
    auth_failed: "bad",
    unreachable: "bad",
    disabled: "bad",
    failed: "bad",
    planned: "warn",
  };
  const labels = {
    ready: "可用",
    reachable: "可达",
    enabled: "已启用",
    success: "已完成",
    deploying: "部署中",
    provisioning: "配置中",
    running: "运行中",
    auth_failed: "认证失败",
    unreachable: "不可达",
    disabled: "已停用",
    failed: "失败",
    planned: "待部署",
  };
  return `<span class="badge ${map[status] || ""}">${escapeHtml(labels[status] || status || "新建")}</span>`;
}

function bytes(value) {
  if (!value) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let size = Number(value);
  let index = 0;
  while (size >= 1024 && index < units.length - 1) {
    size /= 1024;
    index += 1;
  }
  return `${size.toFixed(index ? 1 : 0)} ${units[index]}`;
}

function gb(value) {
  return (Number(value) / 1024 / 1024 / 1024).toFixed(0);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function copy(text) {
  navigator.clipboard.writeText(text).then(
    () => toast("已复制"),
    () => toast("复制失败")
  );
}

function absoluteUrl(value) {
  const text = String(value || "");
  if (!text || /^https?:\/\//i.test(text)) return text;
  return `${window.location.origin}${text.startsWith("/") ? "" : "/"}${text}`;
}

async function refresh() {
  const [summary, servers, deployments, subscriptions, chains, clients] = await Promise.all([
    api("/api/summary"),
    api("/api/servers"),
    api("/api/deployments"),
    api("/api/subscriptions"),
    api("/api/chains"),
    api("/api/clients"),
  ]);
  state.summary = summary;
  state.servers = servers.servers;
  state.deployments = deployments.deployments;
  state.subscriptions = subscriptions.subscriptions;
  state.chains = chains.chains;
  state.clients = clients.clients;
  render();
}

function render() {
  renderSummary();
  renderServers();
  renderDeployments();
  renderSubscriptions();
  renderChains();
  renderClients();
  renderSelects();
  $("#statusLine").textContent = `${state.servers.length} 台服务器，${state.deployments.length} 个部署，${state.chains.length} 条代理链，${state.subscriptions.length} 条订阅，${state.clients.length} 个客户端`;
}

function renderSummary() {
  $("#metricServers").textContent = state.summary?.servers ?? 0;
  $("#metricDeployments").textContent = state.summary?.readyDeployments ?? 0;
  $("#metricClients").textContent = state.summary?.clients ?? 0;
  $("#metricExpiring").textContent = state.summary?.expiringClients ?? 0;

  $("#overviewServers").innerHTML = state.servers.slice(0, 4).map(serverItem).join("") || empty("暂无服务器");
  $("#overviewDeployments").innerHTML =
    state.deployments.slice(0, 4).map(deploymentItem).join("") || empty("暂无部署");
}

function renderServers() {
  $("#serverList").innerHTML =
    state.servers.map((server) => serverItem(server, { allowDelete: true })).join("") ||
    empty("暂无服务器");
}

function serverItem(server, options = {}) {
  return `
    <article class="item">
      <div class="item-head">
        <div class="item-title">
          <strong>${escapeHtml(server.name)}</strong>
          <small>${escapeHtml(server.ssh_user)}@${escapeHtml(server.host)}:${server.ssh_port}</small>
        </div>
        ${statusBadge(server.status)}
      </div>
      <div class="meta">认证：${escapeHtml(server.auth_type)} · 密钥：${escapeHtml(server.secret_label)}</div>
      ${server.host_key_fingerprint ? `<div class="meta">SSH 指纹：<span class="mono">${escapeHtml(server.host_key_fingerprint)}</span> · ${server.host_key_trusted ? "已信任" : "等待核验"}</div>` : ""}
      <div class="item-actions">
        <button class="secondary" data-test-server="${server.id}">测试连接</button>
        ${server.host_key_fingerprint && !server.host_key_trusted ? `<button class="primary" data-approve-host-key="${server.id}">核验后信任</button>` : ""}
        ${server.host_key_trusted ? `<button class="ghost" data-reset-host-key="${server.id}">重置指纹</button>` : ""}
        <button class="primary" data-deploy-server="${server.id}">部署</button>
        ${options.allowDelete ? `<button class="danger" data-delete-server="${server.id}">删除</button>` : ""}
      </div>
    </article>
  `;
}

function renderDeployments() {
  $("#deploymentList").innerHTML =
    state.deployments.map((deployment) => deploymentItem(deployment, { allowDelete: true })).join("") ||
    empty("暂无部署");
}

function renderSubscriptions() {
  $("#subscriptionList").innerHTML =
    state.subscriptions.map(subscriptionItem).join("") || empty("暂无订阅");
}

function renderChains() {
  $("#chainList").innerHTML =
    state.chains.map(chainItem).join("") || empty("暂无代理链");
  renderChainBuilder();
}

function chainItem(chain) {
  const subscriptionUrl = absoluteUrl(chain.subscription_url);
  const hopSummary = (chain.hops || [])
    .map((hop) => `${hop.fromServerName} — ${chainProtocolLabel(hop.protocol)} → ${hop.toServerName}`)
    .join(" · ");
  return `
    <article class="item">
      <div class="item-head">
        <div class="item-title">
          <strong>${escapeHtml(chain.name)}</strong>
          <small>${escapeHtml(chain.path || "未配置路径")}</small>
        </div>
        ${statusBadge(chain.status)}
      </div>
      <div class="meta">入口：${escapeHtml(chain.entry_server_name || "-")} · 出口：${escapeHtml(chain.exit_server_name || "-")}</div>
      ${hopSummary ? `<div class="chain-route-summary">${escapeHtml(hopSummary)}</div>` : ""}
      ${chain.last_error ? `<div class="meta bad-text">错误：${escapeHtml(chain.last_error)}</div>` : ""}
      <div class="meta">订阅：<span class="mono">${escapeHtml(subscriptionUrl)}</span></div>
      <div class="mono">${chain.share_link ? escapeHtml(chain.share_link) : "下发成功后生成入口节点链接"}</div>
      <div class="item-actions">
        <button class="primary" data-deploy-chain="${chain.id}">
          ${chain.status === "ready" ? "重新下发" : "下发远端"}
        </button>
        <button class="secondary" data-copy="${escapeHtml(subscriptionUrl)}">复制订阅</button>
        <button class="secondary" data-rotate-chain-token="${chain.id}">轮换订阅令牌</button>
        ${chain.share_link ? `<button class="secondary" data-copy="${escapeHtml(chain.share_link)}">复制入口节点</button>` : ""}
        <button class="danger" data-delete-chain="${chain.id}">删除</button>
      </div>
    </article>
  `;
}

function readyDeployments() {
  return state.deployments.filter((deployment) => deployment.status === "ready");
}

function chainProtocolLabel(protocol) {
  return protocol === CHAIN_PROTOCOL_SHADOWSOCKS_2022
    ? "SS2022"
    : "VLESS + REALITY";
}

function chainEdgeKey(fromDeploymentId, toDeploymentId) {
  return `${fromDeploymentId}::${toDeploymentId}`;
}

function chainProtocolFor(fromDeploymentId, toDeploymentId) {
  return state.chainProtocolDraft[chainEdgeKey(fromDeploymentId, toDeploymentId)] ||
    CHAIN_PROTOCOL_SHADOWSOCKS_2022;
}

function chainLinkProtocols() {
  return state.chainDraft.slice(1).map((deploymentId, index) =>
    chainProtocolFor(state.chainDraft[index], deploymentId)
  );
}

function chainPreviewText(selected) {
  if (!selected.length) return "未选择";
  let preview = `客户端 — VLESS + REALITY → ${selected[0].server_name}`;
  for (let index = 1; index < selected.length; index += 1) {
    const protocol = chainProtocolFor(selected[index - 1].id, selected[index].id);
    preview += ` — ${chainProtocolLabel(protocol)} → ${selected[index].server_name}`;
  }
  return preview;
}

function renderChainBuilder() {
  const availableNode = $("#chainAvailableNodes");
  const selectedNode = $("#chainSelectedNodes");
  if (!availableNode || !selectedNode) return;

  const ready = readyDeployments();
  const byId = new Map(ready.map((deployment) => [deployment.id, deployment]));
  state.chainDraft = state.chainDraft.filter((deploymentId) => byId.has(deploymentId));
  const selectedIds = new Set(state.chainDraft);
  const selected = state.chainDraft.map((deploymentId) => byId.get(deploymentId)).filter(Boolean);
  const available = ready.filter((deployment) => !selectedIds.has(deployment.id));

  availableNode.innerHTML =
    available.map((deployment) => chainAvailableItem(deployment)).join("") ||
    empty("暂无可用 ready 部署");
  selectedNode.innerHTML =
    selected.map((deployment, index) => `
      ${index > 0 ? chainHopItem(selected[index - 1], deployment, index) : ""}
      ${chainSelectedItem(deployment, index)}
    `).join("") ||
    `<div class="empty">把节点拖到这里，顺序就是入口到出口</div>`;
  $("#chainPreview").textContent = chainPreviewText(selected);
  $("#chainSubmitBtn").disabled = selected.length < 2;
}

function chainAvailableItem(deployment) {
  return `
    <article class="chain-node" draggable="true" data-chain-drag="deployment" data-deployment-id="${deployment.id}">
      <div>
        <strong>${escapeHtml(deployment.server_name)}</strong>
        <small>${escapeHtml(deployment.host)}:${deployment.proxy_port} · ${escapeHtml(deployment.protocol)}</small>
      </div>
      <button class="secondary" type="button" data-chain-add="${deployment.id}">加入</button>
    </article>
  `;
}

function chainSelectedItem(deployment, index) {
  return `
    <article class="chain-node is-selected" draggable="true" data-chain-drag="selected" data-chain-index="${index}" data-chain-position="${index}">
      <span class="chain-index">${index + 1}</span>
      <div>
        <strong>${escapeHtml(deployment.server_name)}</strong>
        <small>${index === 0 ? "入口 · 客户端经 VLESS + REALITY 接入" : index === state.chainDraft.length - 1 ? "出口" : "中继"} · ${escapeHtml(deployment.host)}:${deployment.proxy_port}</small>
      </div>
      <div class="chain-node-actions">
        <button class="ghost icon-button" type="button" data-chain-up="${index}" title="上移">↑</button>
        <button class="ghost icon-button" type="button" data-chain-down="${index}" title="下移">↓</button>
        <button class="ghost icon-button" type="button" data-chain-remove="${index}" title="移除">×</button>
      </div>
    </article>
  `;
}

function chainHopItem(fromDeployment, toDeployment, destinationIndex) {
  const edgeKey = chainEdgeKey(fromDeployment.id, toDeployment.id);
  const protocol = chainProtocolFor(fromDeployment.id, toDeployment.id);
  return `
    <div class="chain-hop" data-chain-position="${destinationIndex}">
      <span class="chain-hop-arrow">↓</span>
      <label>
        <span>${escapeHtml(fromDeployment.server_name)} 到 ${escapeHtml(toDeployment.server_name)}</span>
        <select data-chain-protocol data-chain-edge="${escapeHtml(edgeKey)}" aria-label="选择节点间协议">
          <option value="${CHAIN_PROTOCOL_SHADOWSOCKS_2022}" ${protocol === CHAIN_PROTOCOL_SHADOWSOCKS_2022 ? "selected" : ""}>Shadowsocks 2022（海外转发）</option>
          <option value="${CHAIN_PROTOCOL_VLESS_REALITY}" ${protocol === CHAIN_PROTOCOL_VLESS_REALITY ? "selected" : ""}>VLESS + REALITY（跨境链路）</option>
        </select>
      </label>
    </div>
  `;
}

function addChainDeployment(deploymentId, index = state.chainDraft.length) {
  if (state.chainDraft.includes(deploymentId)) return;
  const safeIndex = Math.max(0, Math.min(index, state.chainDraft.length));
  state.chainDraft.splice(safeIndex, 0, deploymentId);
  renderChainBuilder();
}

function removeChainDeployment(index) {
  state.chainDraft.splice(index, 1);
  renderChainBuilder();
}

function moveChainDeployment(fromIndex, toIndex) {
  if (fromIndex === toIndex || fromIndex < 0 || fromIndex >= state.chainDraft.length) return;
  const [deploymentId] = state.chainDraft.splice(fromIndex, 1);
  const adjusted = toIndex > fromIndex ? toIndex - 1 : toIndex;
  const safeIndex = Math.max(0, Math.min(adjusted, state.chainDraft.length));
  state.chainDraft.splice(safeIndex, 0, deploymentId);
  renderChainBuilder();
}

function chainDropIndex(target) {
  const positioned = target.closest("[data-chain-position]");
  if (!positioned) return state.chainDraft.length;
  return Number(positioned.dataset.chainPosition);
}

function deploymentItem(deployment, options = {}) {
  const subscriptionUrl = absoluteUrl(deployment.subscription_url);
  return `
    <article class="item">
      <div class="item-head">
        <div class="item-title">
          <strong>${escapeHtml(deployment.server_name)} · ${escapeHtml(deployment.engine)}</strong>
          <small>${escapeHtml(deployment.protocol)}</small>
        </div>
        ${statusBadge(deployment.status)}
      </div>
      <div class="meta">面板：<span class="mono">127.0.0.1:${deployment.panel_port}${escapeHtml(deployment.panel_path)}</span>（仅 SSH 隧道）</div>
      <div class="meta">面板账号由控制器加密保管；面板仅允许通过 SSH 隧道访问</div>
      <div class="meta">入站 ID：<span class="mono">${escapeHtml(deployment.xui_inbound_id || "未同步")}</span></div>
      <div class="meta">伪装目标：<span class="mono">${escapeHtml(deployment.reality_dest || (deployment.reality_mode === "auto" ? "自动检测中" : "-"))}</span> · ${deployment.reality_mode === "auto" ? "自动选择" : "手动指定"}</div>
      <div class="meta">默认订阅：<span class="mono">${escapeHtml(subscriptionUrl)}</span></div>
      <div class="item-actions">
        <button class="ghost" data-section-jump="subscriptions">管理订阅</button>
        ${options.allowDelete ? `<button class="danger" data-delete-deployment="${deployment.id}">删除</button>` : ""}
      </div>
    </article>
  `;
}

function subscriptionItem(subscription) {
  const subscriptionUrl = absoluteUrl(subscription.subscription_url);
  return `
    <article class="item subscription-item">
      <div class="item-head">
        <div class="item-title">
          <strong>${escapeHtml(subscription.name)}</strong>
          <small>更新于 ${escapeHtml(subscription.updated_at)}</small>
        </div>
        <span class="badge ok">${Number(subscription.node_count || 0)} 个节点</span>
      </div>
      <div class="sub-link-row compact">
        <span class="mono">${escapeHtml(subscriptionUrl)}</span>
        <button class="secondary" data-copy="${escapeHtml(subscriptionUrl)}">复制链接</button>
      </div>
      <div class="meta">节点总流量：${bytes(subscription.quota_bytes)}</div>
      <div class="item-actions">
        <button class="primary" data-edit-subscription="${subscription.id}">分发和调整</button>
        <button class="secondary" data-rotate-subscription-token="${subscription.id}">轮换令牌</button>
        <button class="danger" data-delete-subscription="${subscription.id}">删除</button>
      </div>
    </article>
  `;
}

function renderClients() {
  $("#clientList").innerHTML = state.clients.map(clientItem).join("") || empty("暂无客户端");
}

function clientItem(client) {
  const percent = client.quota_bytes > 0
    ? Math.min(100, Math.round((client.used_bytes / client.quota_bytes) * 100))
    : 0;
  return `
    <article class="item">
      <div class="item-head">
        <div class="item-title">
          <strong>${escapeHtml(client.name)}</strong>
          <small>${escapeHtml(client.server_name)} · 到期 ${escapeHtml(client.expires_at)}</small>
        </div>
        ${statusBadge(client.enabled ? "enabled" : "disabled")}
      </div>
      <div class="progress"><span style="width: ${percent}%"></span></div>
      <div class="meta">${bytes(client.used_bytes)} / ${bytes(client.quota_bytes)} · UUID <span class="mono">${escapeHtml(client.uuid)}</span></div>
      <div class="mono">${escapeHtml(client.share_link)}</div>
      <div class="item-actions">
        <button class="secondary" data-copy="${escapeHtml(client.share_link)}">复制节点</button>
        <button class="ghost" data-edit-client="${client.id}">编辑</button>
        <button class="ghost" data-reset-client="${client.id}">重置流量</button>
        <button class="ghost" data-toggle-client="${client.id}" data-enabled="${client.enabled ? 0 : 1}">
          ${client.enabled ? "禁用" : "启用"}
        </button>
      </div>
    </article>
  `;
}

function renderSelects() {
  const serverOptions = state.servers
    .map((server) => `<option value="${server.id}">${escapeHtml(server.name)} · ${escapeHtml(server.host)}</option>`)
    .join("");
  $("#deployServerSelect").innerHTML = serverOptions || `<option value="">先添加服务器</option>`;

  const deploymentOptions = state.deployments
    .filter((deployment) => deployment.status === "ready")
    .map((deployment) => `<option value="${deployment.id}">${escapeHtml(deployment.server_name)} · ${escapeHtml(deployment.protocol)}</option>`)
    .join("");
  $("#clientDeploymentSelect").innerHTML = deploymentOptions || `<option value="">先完成部署</option>`;
}

function empty(text) {
  return `<div class="empty">${text}</div>`;
}

function openClientEdit(clientId) {
  const client = state.clients.find((item) => item.id === clientId);
  if (!client) return toast("客户端不存在");
  const form = $("#clientEditForm");
  form.elements.id.value = client.id;
  form.elements.name.value = client.name;
  form.elements.quotaGb.value = gb(client.quota_bytes);
  $("#clientEditDialog").showModal();
}

function closeClientEdit() {
  $("#clientEditDialog").close();
  $("#clientEditForm").reset();
}

async function openSubscriptionEdit(subscriptionId) {
  const config = await api(`/api/subscriptions/${subscriptionId}`);
  const selected = new Map(config.selectedNodes.map((item) => [item.nodeClientId, item]));
  const form = $("#subscriptionForm");
  const url = absoluteUrl(config.subscription.subscription_url);
  form.elements.subscriptionId.value = subscriptionId;
  form.elements.name.value = config.subscription.name;
  $("#subscriptionTitle").textContent = "分发和调整";
  $("#subscriptionUrlValue").textContent = url;
  $("#subscriptionCopyBtn").dataset.copy = url;
  $("#subscriptionNodeList").innerHTML =
    config.availableNodes.map((node) => subscriptionNodeItem(node, selected.get(node.id))).join("") ||
    empty("暂无可选节点");
  $("#subscriptionDialog").showModal();
}

function subscriptionNodeItem(node, selected) {
  const selectedQuota = selected?.quotaBytes ?? node.quota_bytes;
  return `
    <label class="node-option">
      <input type="checkbox" name="nodeIds" value="${escapeHtml(node.id)}" ${selected ? "checked" : ""} />
      <span>
        <strong>${escapeHtml(node.name)}</strong>
        <small>${escapeHtml(node.server_name)} · ${bytes(node.quota_bytes)} · ${node.enabled ? "启用" : "禁用"}</small>
        <span class="mono">${escapeHtml(node.share_link)}</span>
        <span class="quota-line">
          流量 GB
          <input name="quotaGb:${escapeHtml(node.id)}" type="number" min="0" step="1" value="${escapeHtml(gb(selectedQuota))}" />
        </span>
      </span>
    </label>
  `;
}

function closeSubscriptionEdit() {
  $("#subscriptionDialog").close();
  $("#subscriptionForm").reset();
  $("#subscriptionNodeList").innerHTML = "";
}

async function pollJob(jobId) {
  clearInterval(state.jobTimer);
  state.activeJobId = jobId;
  setSection("logs");

  const tick = async () => {
    const job = await api(`/api/jobs/${jobId}`);
    $("#jobStatus").textContent = job.status;
    $("#jobStatus").className = `badge ${job.status === "success" ? "ok" : job.status === "failed" ? "bad" : "warn"}`;
    $("#jobLog").textContent = job.logs.map((entry) => `[${entry.at}] ${entry.line}`).join("\n");
    $("#jobLog").scrollTop = $("#jobLog").scrollHeight;
    if (job.status === "success" || job.status === "failed") {
      clearInterval(state.jobTimer);
      await refresh();
    }
  };

  await tick();
  state.jobTimer = setInterval(tick, 800);
}

function syncRealityTargetFields() {
  const manual = $("#realityMode").value === "manual";
  $("#realityManualFields").hidden = !manual;
  $("#deployForm").realityDest.required = manual;
}

function bindEvents() {
  $("#realityMode").addEventListener("change", syncRealityTargetFields);
  syncRealityTargetFields();
  $$(".nav-item").forEach((button) => {
    button.addEventListener("click", () => setSection(button.dataset.section));
  });
  $$("[data-section-jump]").forEach((button) => {
    button.addEventListener("click", () => setSection(button.dataset.sectionJump));
  });
  $("#refreshBtn").addEventListener("click", () => refresh().then(() => toast("已刷新")));
  $("#logoutBtn").addEventListener("click", () => logout());

  $("#serverForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    await api("/api/servers", {
      method: "POST",
      body: JSON.stringify(formData(form)),
    });
    form.reset();
    form.sshPort.value = 22;
    form.sshUser.value = "root";
    toast("服务器已保存");
    await refresh();
  });

  $("#deployForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = formData(form);
    if (!data.serverId) return toast("请选择服务器");
    data.installMethod = "native";
    const result = await api(`/api/servers/${data.serverId}/deploy`, {
      method: "POST",
      body: JSON.stringify(data),
    });
    toast("部署任务已创建");
    await pollJob(result.job.id);
  });

  $("#clientForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = formData(form);
    if (!data.deploymentId) return toast("请选择部署");
    await api(`/api/deployments/${data.deploymentId}/clients`, {
      method: "POST",
      body: JSON.stringify(data),
    });
    form.reset();
    toast("客户端已创建");
    await refresh();
  });

  $("#subscriptionCreateForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = formData(form);
    const subscription = await api("/api/subscriptions", {
      method: "POST",
      body: JSON.stringify(data),
    });
    form.reset();
    toast("订阅已创建");
    await refresh();
    await openSubscriptionEdit(subscription.id);
  });

  $("#chainForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = formData(form);
    if (state.chainDraft.length < 2) return toast("至少选择两个部署节点");
    await api("/api/chains", {
      method: "POST",
      body: JSON.stringify({
        name: data.name,
        deploymentIds: state.chainDraft,
        linkProtocols: chainLinkProtocols(),
      }),
    });
    state.chainDraft = [];
    state.chainProtocolDraft = {};
    form.reset();
    toast("代理链已保存");
    await refresh();
  });

  $("#clientEditForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = formData(form);
    const client = state.clients.find((item) => item.id === data.id);
    if (!client) return toast("客户端不存在");
    await api(`/api/clients/${data.id}`, {
      method: "PATCH",
      body: JSON.stringify({
        name: data.name,
        quotaGb: data.quotaGb,
        expiresAt: client.expires_at,
        enabled: Boolean(client.enabled),
      }),
    });
    closeClientEdit();
    toast("客户端已更新");
    await refresh();
  });

  $("#subscriptionForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const subscriptionId = form.elements.subscriptionId.value;
    const nodes = Array.from(form.querySelectorAll('input[name="nodeIds"]:checked'))
      .map((input) => ({
        nodeId: input.value,
        quotaGb: form.elements[`quotaGb:${input.value}`]?.value || 0,
      }));
    await api(`/api/subscriptions/${subscriptionId}`, {
      method: "PATCH",
      body: JSON.stringify({
        name: form.elements.name.value,
        nodes,
      }),
    });
    closeSubscriptionEdit();
    toast("订阅节点已更新");
    await refresh();
  });

  document.body.addEventListener("dragstart", (event) => {
    const node = event.target.closest("[data-chain-drag]");
    if (!node) return;
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData(
      "text/plain",
      JSON.stringify({
        type: node.dataset.chainDrag,
        deploymentId: node.dataset.deploymentId || "",
        index: Number(node.dataset.chainIndex || -1),
      })
    );
  });

  document.body.addEventListener("dragover", (event) => {
    if (event.target.closest("#chainSelectedNodes")) {
      event.preventDefault();
    }
  });

  document.body.addEventListener("drop", (event) => {
    if (!event.target.closest("#chainSelectedNodes")) return;
    event.preventDefault();
    let payload;
    try {
      payload = JSON.parse(event.dataTransfer.getData("text/plain"));
    } catch {
      return;
    }
    const index = chainDropIndex(event.target);
    if (payload.type === "deployment" && payload.deploymentId) {
      addChainDeployment(payload.deploymentId, index);
    }
    if (payload.type === "selected") {
      moveChainDeployment(Number(payload.index), index);
    }
  });

  document.body.addEventListener("change", (event) => {
    const selector = event.target.closest("[data-chain-protocol]");
    if (!selector) return;
    state.chainProtocolDraft[selector.dataset.chainEdge] = selector.value;
    renderChainBuilder();
  });

  document.body.addEventListener("click", async (event) => {
    const target = event.target.closest("button");
    if (!target) return;

    if (target.dataset.closeClientEdit !== undefined) {
      closeClientEdit();
    }

    if (target.dataset.closeSubscriptionEdit !== undefined) {
      closeSubscriptionEdit();
    }

    if (target.dataset.copy) {
      copy(target.dataset.copy);
    }

    if (target.dataset.chainAdd) {
      addChainDeployment(target.dataset.chainAdd);
      return;
    }

    if (target.dataset.chainRemove !== undefined) {
      removeChainDeployment(Number(target.dataset.chainRemove));
      return;
    }

    if (target.dataset.chainUp !== undefined) {
      const index = Number(target.dataset.chainUp);
      moveChainDeployment(index, index - 1);
      return;
    }

    if (target.dataset.chainDown !== undefined) {
      const index = Number(target.dataset.chainDown);
      moveChainDeployment(index, index + 2);
      return;
    }

    if (target.dataset.sectionJump) {
      setSection(target.dataset.sectionJump);
    }

    if (target.dataset.testServer) {
      const result = await api(`/api/servers/${target.dataset.testServer}/test`, {
        method: "POST",
        body: "{}",
      });
      toast(result.status === "reachable" ? "SSH 可达" : `检测失败：${result.error}`);
      await refresh();
    }

    if (target.dataset.approveHostKey) {
      const server = state.servers.find((item) => item.id === target.dataset.approveHostKey);
      if (!confirm(`请先通过 VPS 控制台核对 SSH 指纹：\n${server?.host_key_fingerprint || ""}\n\n确认完全一致后再信任。`)) return;
      await api(`/api/servers/${target.dataset.approveHostKey}/host-key/approve`, {
        method: "POST",
        body: "{}",
      });
      toast("SSH 主机指纹已信任，请重新测试连接");
      await refresh();
    }

    if (target.dataset.resetHostKey) {
      if (!confirm("仅在 VPS 已确认重装或更换 SSH 主机密钥后重置。继续吗？")) return;
      await api(`/api/servers/${target.dataset.resetHostKey}/host-key/reset`, {
        method: "POST",
        body: "{}",
      });
      toast("已清除 SSH 主机指纹，请重新测试并核验");
      await refresh();
    }

    if (target.dataset.deployServer) {
      setSection("deployments");
      $("#deployServerSelect").value = target.dataset.deployServer;
    }

    if (target.dataset.deleteServer) {
      const server = state.servers.find((item) => item.id === target.dataset.deleteServer);
      if (!confirm(`删除服务器 ${server?.name || ""}？这会同步卸载远端 3x-ui 并删除本地记录。`)) return;
      await api(`/api/servers/${target.dataset.deleteServer}`, {
        method: "DELETE",
      });
      toast("服务器已删除");
      await refresh();
    }

    if (target.dataset.deleteDeployment) {
      const deployment = state.deployments.find((item) => item.id === target.dataset.deleteDeployment);
      if (!confirm(`删除部署 ${deployment?.server_name || ""}？这会同步清理远端部署内容并删除本地记录。`)) return;
      await api(`/api/deployments/${target.dataset.deleteDeployment}`, {
        method: "DELETE",
      });
      toast("部署已删除");
      await refresh();
    }

    if (target.dataset.editSubscription) {
      await openSubscriptionEdit(target.dataset.editSubscription);
    }

    if (target.dataset.deleteSubscription) {
      if (!confirm("删除这条订阅链接？")) return;
      await api(`/api/subscriptions/${target.dataset.deleteSubscription}`, {
        method: "DELETE",
      });
      toast("订阅已删除");
      await refresh();
    }

    if (target.dataset.rotateSubscriptionToken) {
      if (!confirm("轮换后旧订阅链接会立即失效，继续吗？")) return;
      await api(`/api/subscriptions/${target.dataset.rotateSubscriptionToken}/rotate-token`, {
        method: "POST",
        body: "{}",
      });
      toast("订阅令牌已轮换");
      await refresh();
    }

    if (target.dataset.deleteChain) {
      const chain = state.chains.find((item) => item.id === target.dataset.deleteChain);
      if (!confirm(`删除代理链 ${chain?.name || ""}？`)) return;
      await api(`/api/chains/${target.dataset.deleteChain}`, {
        method: "DELETE",
      });
      toast("代理链已删除");
      await refresh();
    }

    if (target.dataset.rotateChainToken) {
      if (!confirm("轮换后旧代理链订阅链接会立即失效，继续吗？")) return;
      await api(`/api/chains/${target.dataset.rotateChainToken}/rotate-token`, {
        method: "POST",
        body: "{}",
      });
      toast("代理链订阅令牌已轮换");
      await refresh();
    }

    if (target.dataset.deployChain) {
      const result = await api(`/api/chains/${target.dataset.deployChain}/deploy`, {
        method: "POST",
        body: "{}",
      });
      toast("代理链下发任务已创建");
      await pollJob(result.job.id);
    }

    if (target.dataset.editClient) {
      openClientEdit(target.dataset.editClient);
    }

    if (target.dataset.resetClient) {
      await api(`/api/clients/${target.dataset.resetClient}/reset`, {
        method: "POST",
        body: "{}",
      });
      toast("流量已重置");
      await refresh();
    }

    if (target.dataset.toggleClient) {
      const client = state.clients.find((item) => item.id === target.dataset.toggleClient);
      await api(`/api/clients/${target.dataset.toggleClient}`, {
        method: "PATCH",
        body: JSON.stringify({
          name: client.name,
          quotaGb: gb(client.quota_bytes),
          expiresAt: client.expires_at,
          enabled: Number(target.dataset.enabled) === 1,
        }),
      });
      toast("客户端状态已更新");
      await refresh();
    }
  });
}

bindEvents();
api("/api/auth/session")
  .then((session) => {
    const warning = $("#securityWarning");
    warning.textContent = session.securityWarning || "";
    warning.hidden = !session.securityWarning;
    return refresh();
  })
  .catch((error) => toast(error.message));
