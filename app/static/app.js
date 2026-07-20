const state = {
  summary: null,
  servers: [],
  deployments: [],
  subscriptions: [],
  chains: [],
  clients: [],
  webSettings: null,
  chainDraft: [],
  chainProtocolDraft: {},
  chainPortDraft: {},
  activeJobId: null,
  jobTimer: null,
  jobLogSeq: 0,
  jobLogs: [],
};

const CHAIN_PROTOCOL_VLESS_REALITY = "vless_reality";
const CHAIN_PROTOCOL_SHADOWSOCKS_2022 = "shadowsocks_2022";

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

function csrfToken() {
  const cookies = document.cookie.split(";").map((item) => item.trim());
  const entry = ["__Host-myn_csrf=", "myn_csrf="]
    .map((prefix) => cookies.find((item) => item.startsWith(prefix)))
    .find(Boolean);
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

function syncNeverExpires(form, requireDate = false) {
  const neverExpires = form.elements.neverExpires;
  const expiresAt = form.elements.expiresAt;
  if (!neverExpires || !expiresAt) return;
  expiresAt.disabled = neverExpires.checked;
  expiresAt.required = requireDate && !neverExpires.checked;
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
    clients: ["ACCESS", "用户"],
    logs: ["ACTIVITY", "任务日志"],
    settings: ["CONFIGURATION", "设置"],
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

function legacyCopy(text) {
  const input = document.createElement("textarea");
  input.value = text;
  input.setAttribute("readonly", "");
  input.style.position = "fixed";
  input.style.left = "-9999px";
  document.body.appendChild(input);
  try {
    input.select();
    input.setSelectionRange(0, input.value.length);
    return document.execCommand("copy");
  } finally {
    input.remove();
  }
}

async function copy(text) {
  const value = String(text || "");
  if (!value) {
    toast("没有可复制的内容");
    return;
  }

  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(value);
    } else if (!legacyCopy(value)) {
      throw new Error("clipboard unavailable");
    }
    toast("已复制");
  } catch (_error) {
    // Clipboard permissions can still be denied in a secure context.
    try {
      if (legacyCopy(value)) {
        toast("已复制");
        return;
      }
    } catch (_fallbackError) {
      // Fall through to the actionable error below.
    }
    toast("复制失败，请长按链接手动复制");
  }
}

function effectivePublicOrigin() {
  if (state.webSettings?.source === "automatic") return window.location.origin;
  return state.webSettings?.publicOrigin || window.location.origin;
}

function absoluteUrl(value) {
  const text = String(value || "");
  if (!text || /^https?:\/\//i.test(text)) return text;
  const origin = effectivePublicOrigin();
  return `${origin}${text.startsWith("/") ? "" : "/"}${text}`;
}

function subscriptionUrlFor(value, format) {
  const url = new URL(absoluteUrl(value));
  url.searchParams.set("format", format);
  return url.toString();
}

async function refresh() {
  const [summary, servers, deployments, subscriptions, chains, clients, webSettings] = await Promise.all([
    api("/api/summary"),
    api("/api/servers"),
    api("/api/deployments"),
    api("/api/subscriptions"),
    api("/api/chains"),
    api("/api/clients"),
    api("/api/settings"),
  ]);
  state.summary = summary;
  state.servers = servers.servers;
  state.deployments = deployments.deployments;
  state.subscriptions = subscriptions.subscriptions;
  state.chains = chains.chains;
  state.clients = clients.clients;
  state.webSettings = webSettings;
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
  renderWebSettings();
  $("#statusLine").textContent = `${state.servers.length} 台服务器，${state.deployments.length} 个部署，${state.chains.length} 条代理链，${state.subscriptions.length} 条订阅，${state.clients.length} 名用户`;
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

function healthLabel(server) {
  const labels = {
    reachable: "可达",
    auth_failed: "认证失败",
    unreachable: "不可达",
    new: "未检查",
  };
  const latency = Number(server.last_latency_ms);
  if (server.status === "reachable" && Number.isFinite(latency)) {
    return `可达 · ${latency} ms`;
  }
  return escapeHtml(labels[server.status] || server.status || "未知");
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
      <div class="meta">健康：${healthLabel(server)} · 最近检查 ${server.last_check_at ? escapeHtml(server.last_check_at) : "从未"}</div>
      ${server.last_health_error ? `<div class="meta">最近错误：<span class="mono">${escapeHtml(server.last_health_error)}</span></div>` : ""}
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
  const subscriptionUrl = subscriptionUrlFor(chain.subscription_url, "mihomo");
  const base64SubscriptionUrl = subscriptionUrlFor(chain.subscription_url, "base64");
  const subscriptionReady = Boolean(chain.share_link);
  const hopSummary = (chain.hops || [])
    .map((hop) => `${hop.fromServerName} — ${chainProtocolLabel(hop.protocol)} → ${hop.toServerName}`)
    .join(" · ");
  const endpointSummary = (chain.nodes || [])
    .map((node) => `${node.server_name} ${displayEndpoint(node.host, node.inbound_port || "未配置")}`)
    .join(" → ");
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
      ${endpointSummary ? `<div class="meta">对等映射端口：<span class="mono">${escapeHtml(endpointSummary)}</span></div>` : ""}
      ${hopSummary ? `<div class="chain-route-summary">${escapeHtml(hopSummary)}</div>` : ""}
      ${chain.last_error ? `<div class="meta bad-text">错误：${escapeHtml(chain.last_error)}</div>` : ""}
      <div class="meta">Mihomo / Clash 订阅：<span class="mono">${subscriptionReady ? escapeHtml(subscriptionUrl) : "下发成功后可用"}</span></div>
      <div class="mono">${chain.share_link ? escapeHtml(chain.share_link) : "下发成功后生成入口节点链接"}</div>
      <div class="item-actions">
        <button class="primary" data-deploy-chain="${chain.id}">
          ${chain.status === "ready" ? "重新下发" : "下发远端"}
        </button>
        <button class="secondary" ${subscriptionReady ? `data-copy="${escapeHtml(subscriptionUrl)}"` : "disabled title=\"请先下发远端\""}>${subscriptionReady ? "复制 Mihomo / Clash 订阅" : "下发后可复制订阅"}</button>
        ${subscriptionReady ? `<button class="secondary" data-copy="${escapeHtml(base64SubscriptionUrl)}">复制通用 Base64 订阅</button>` : ""}
        <button class="secondary" data-rotate-chain-token="${chain.id}">轮换订阅令牌</button>
        ${chain.share_link ? `<button class="secondary" data-copy="${escapeHtml(chain.share_link)}">复制入口节点</button>` : ""}
        ${chain.share_link ? `<button class="ghost" data-qr="${escapeHtml(chain.share_link)}" data-qr-title="${escapeHtml(chain.name)}">二维码</button>` : ""}
        <button class="danger" data-delete-chain="${chain.id}">删除</button>
      </div>
    </article>
  `;
}

function readyDeployments() {
  return state.deployments.filter(
    (deployment) => deployment.status === "ready" && deployment.install_method === "native",
  );
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
    CHAIN_PROTOCOL_VLESS_REALITY;
}

function chainLinkProtocols() {
  return state.chainDraft.slice(1).map((deploymentId, index) =>
    chainProtocolFor(state.chainDraft[index], deploymentId)
  );
}

function chainPortFor(deploymentId) {
  return String(state.chainPortDraft[deploymentId] ?? "").trim();
}

function chainInboundPorts() {
  return state.chainDraft.map((deploymentId) => Number(chainPortFor(deploymentId)));
}

function chainPortsValid() {
  return state.chainDraft.every((deploymentId) => {
    const raw = chainPortFor(deploymentId);
    const port = Number(raw);
    return /^\d+$/.test(raw) && Number.isInteger(port) && port >= 1 && port <= 65535;
  });
}

function displayEndpoint(host, port) {
  const renderedHost = String(host).includes(":") ? `[${host}]` : host;
  return `${renderedHost}:${port || "待填写"}`;
}

function updateChainSubmitState() {
  const button = $("#chainSubmitBtn");
  if (button) button.disabled = state.chainDraft.length < 2 || !chainPortsValid();
}

function chainPreviewText(selected) {
  if (!selected.length) return "未选择";
  let preview = `用户设备 — VLESS + REALITY → ${displayEndpoint(selected[0].host, chainPortFor(selected[0].id))}`;
  for (let index = 1; index < selected.length; index += 1) {
    const protocol = chainProtocolFor(selected[index - 1].id, selected[index].id);
    preview += ` — ${chainProtocolLabel(protocol)} → ${displayEndpoint(selected[index].host, chainPortFor(selected[index].id))}`;
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
  updateChainSubmitState();
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
  const inboundProtocol = index === 0
    ? CHAIN_PROTOCOL_VLESS_REALITY
    : chainProtocolFor(state.chainDraft[index - 1], deployment.id);
  const transportHint = inboundProtocol === CHAIN_PROTOCOL_SHADOWSOCKS_2022 ? "TCP + UDP" : "TCP";
  return `
    <article class="chain-node is-selected" draggable="true" data-chain-drag="selected" data-chain-index="${index}" data-chain-position="${index}">
      <span class="chain-index">${index + 1}</span>
      <div class="chain-node-main">
        <strong>${escapeHtml(deployment.server_name)}</strong>
        <small>${index === 0 ? "入口 · 用户设备经 VLESS + REALITY 接入" : index === state.chainDraft.length - 1 ? "出口" : "中继"} · ${escapeHtml(deployment.host)}:${deployment.proxy_port}</small>
        <label class="chain-port-field">
          <span>对等映射链路端口 · ${transportHint}</span>
          <input data-chain-port data-deployment-id="${escapeHtml(deployment.id)}" type="number" min="1" max="65535" inputmode="numeric" placeholder="例如 31001" value="${escapeHtml(chainPortFor(deployment.id))}" required />
        </label>
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
          <option value="${CHAIN_PROTOCOL_VLESS_REALITY}" ${protocol === CHAIN_PROTOCOL_VLESS_REALITY ? "selected" : ""}>VLESS + REALITY（TCP，适合 NAT）</option>
          <option value="${CHAIN_PROTOCOL_SHADOWSOCKS_2022}" ${protocol === CHAIN_PROTOCOL_SHADOWSOCKS_2022 ? "selected" : ""}>Shadowsocks 2022（需 TCP + UDP）</option>
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
  const [deploymentId] = state.chainDraft.splice(index, 1);
  if (deploymentId) delete state.chainPortDraft[deploymentId];
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
      <div class="meta">用户：${Number(deployment.client_count || 0)} 名（每名用户使用独立 UUID）</div>
      <div class="meta">伪装目标：<span class="mono">${escapeHtml(deployment.reality_dest || (deployment.reality_mode === "auto" ? "自动检测中" : "-"))}</span> · ${deployment.reality_mode === "auto" ? "自动选择" : "手动指定"}</div>
      <div class="item-actions">
        ${deployment.status === "ready" && deployment.install_method === "native" ? `<button class="primary" data-add-user="${deployment.id}">添加用户</button>` : ""}
        <button class="ghost" data-section-jump="subscriptions">管理订阅</button>
        ${options.allowDelete ? `<button class="danger" data-delete-deployment="${deployment.id}">删除</button>` : ""}
      </div>
    </article>
  `;
}

function subscriptionItem(subscription) {
  const subscriptionUrl = absoluteUrl(subscription.subscription_url);
  const nodeCount = Number(subscription.node_count || 0);
  const chainCount = Number(subscription.chain_count || 0);
  return `
    <article class="item subscription-item">
      <div class="item-head">
        <div class="item-title">
          <strong>${escapeHtml(subscription.name)}</strong>
          <small>更新于 ${escapeHtml(subscription.updated_at)}</small>
        </div>
        <span class="badge ok">${nodeCount} 个节点 · ${chainCount} 条代理链</span>
      </div>
      <div class="sub-link-row compact">
        <span class="mono">${escapeHtml(subscriptionUrl)}</span>
        <button class="secondary" data-copy="${escapeHtml(subscriptionUrl)}">复制链接</button>
        <button class="ghost" data-qr="${escapeHtml(subscriptionUrl)}" data-qr-title="${escapeHtml(subscription.name)}">二维码</button>
      </div>
      <div class="meta">普通节点流量：剩余 ${bytes(subscription.remaining_bytes)} · 已用 ${bytes(subscription.used_bytes)} / 总量 ${bytes(subscription.quota_bytes)}</div>
      <div class="item-actions">
        <button class="primary" data-edit-subscription="${subscription.id}">分发和调整</button>
        <button class="secondary" data-rotate-subscription-token="${subscription.id}">轮换令牌</button>
        <button class="danger" data-delete-subscription="${subscription.id}">删除</button>
      </div>
    </article>
  `;
}

function renderClients() {
  const clientsByDeployment = new Map();
  for (const client of state.clients) {
    const users = clientsByDeployment.get(client.deployment_id) || [];
    users.push(client);
    clientsByDeployment.set(client.deployment_id, users);
  }
  $("#clientList").innerHTML = state.deployments.map((deployment) => {
    const users = clientsByDeployment.get(deployment.id) || [];
    return `
      <section class="node-user-group">
        <div class="item-head">
          <div class="item-title">
            <strong>${escapeHtml(deployment.server_name)}</strong>
            <small>${escapeHtml(deployment.protocol)} · ${escapeHtml(deployment.host)}:${deployment.proxy_port}</small>
          </div>
          <span class="badge ${users.length ? "ok" : ""}">${users.length} 名用户</span>
        </div>
        <div class="meta">入站 ID：<span class="mono">${escapeHtml(deployment.xui_inbound_id || "未同步")}</span></div>
        <div class="node-user-list">
          ${users.map(clientItem).join("") || empty("该节点暂无用户")}
        </div>
        ${deployment.status === "ready" ? `<div class="item-actions"><button class="primary" data-add-user="${deployment.id}">＋ 添加用户</button></div>` : ""}
      </section>
    `;
  }).join("") || empty("暂无节点，请先完成部署");
}

function clientItem(client) {
  const percent = client.quota_bytes > 0
    ? Math.min(100, Math.round((client.used_bytes / client.quota_bytes) * 100))
    : 0;
  const resetDays = Number(client.traffic_reset_days || 0);
  const resetLabel = resetDays > 0 ? `每 ${resetDays} 天自动重置` : "不自动重置";
  const expirationLabel = client.expires_at || "不限时";
  return `
    <article class="item">
      <div class="item-head">
        <div class="item-title">
          <strong>${escapeHtml(client.name)}</strong>
          <small>节点 ${escapeHtml(client.server_name)} · 到期 ${escapeHtml(expirationLabel)}</small>
        </div>
        ${statusBadge(client.enabled ? "enabled" : "disabled")}
      </div>
      <div class="progress"><span style="width: ${percent}%"></span></div>
      <div class="meta">${bytes(client.used_bytes)} / ${bytes(client.quota_bytes)} · ${resetLabel} · UUID <span class="mono">${escapeHtml(client.uuid)}</span></div>
      <div class="mono">${escapeHtml(client.share_link)}</div>
      <div class="item-actions">
        <button class="secondary" data-copy="${escapeHtml(client.share_link)}">复制连接</button>
        <button class="ghost" data-qr="${escapeHtml(client.share_link)}" data-qr-title="${escapeHtml(client.name)}">二维码</button>
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
    .map((deployment) => `<option value="${deployment.id}">${escapeHtml(deployment.server_name)} · ${escapeHtml(deployment.protocol)} · ${Number(deployment.client_count || 0)} 名用户</option>`)
    .join("");
  $("#clientDeploymentSelect").innerHTML = deploymentOptions || `<option value="">先完成部署</option>`;
}

function empty(text) {
  return `<div class="empty">${text}</div>`;
}

function openQr(data, title) {
  const value = String(data || "");
  if (!value) return toast("没有可生成二维码的内容");
  const absolute = value.startsWith("/") ? new URL(value, window.location.origin).href : value;
  $("#qrImage").src = `/api/qrcode?data=${encodeURIComponent(absolute)}`;
  $("#qrTitle").textContent = title ? `二维码 · ${title}` : "二维码";
  $("#qrDialog").showModal();
}

function closeQr() {
  $("#qrDialog").close();
  $("#qrImage").removeAttribute("src");
}

function openClientEdit(clientId) {
  const client = state.clients.find((item) => item.id === clientId);
  if (!client) return toast("用户不存在");
  const form = $("#clientEditForm");
  form.elements.id.value = client.id;
  form.elements.name.value = client.name;
  form.elements.quotaGb.value = gb(client.quota_bytes);
  form.elements.trafficResetDays.value = Number(client.traffic_reset_days || 0);
  form.elements.expiresAt.value = client.expires_at || "";
  form.elements.neverExpires.checked = !client.expires_at;
  syncNeverExpires(form, true);
  $("#clientEditDialog").showModal();
}

function closeClientEdit() {
  $("#clientEditDialog").close();
  const form = $("#clientEditForm");
  form.reset();
  syncNeverExpires(form, true);
}

async function openSubscriptionEdit(subscriptionId) {
  const config = await api(`/api/subscriptions/${subscriptionId}`);
  const selected = new Map(config.selectedNodes.map((item) => [item.nodeClientId, item]));
  const selectedChains = new Map(
    (config.selectedChains || (config.selectedChainIds || []).map((chainId) => ({ chainId })))
      .map((item) => [item.chainId, item]),
  );
  const form = $("#subscriptionForm");
  const url = absoluteUrl(config.subscription.subscription_url);
  form.elements.subscriptionId.value = subscriptionId;
  form.elements.name.value = config.subscription.name;
  $("#subscriptionTitle").textContent = "分发和调整";
  $("#subscriptionUrlValue").textContent = url;
  $("#subscriptionCopyBtn").dataset.copy = url;
  const nodeOptions = config.availableNodes
    .map((node) => subscriptionNodeItem(node, selected.get(node.id)))
    .join("");
  const chainOptions = (config.availableChains || [])
    .map((chain) => subscriptionChainItem(chain, selectedChains.get(chain.id)))
    .join("");
  $("#subscriptionNodeList").innerHTML = [
    nodeOptions ? `<div class="subscription-picker-heading">普通节点</div>${nodeOptions}` : "",
    chainOptions ? `<div class="subscription-picker-heading">代理链</div>${chainOptions}` : "",
  ].join("") || empty("暂无可选节点或代理链");
  $("#subscriptionDialog").showModal();
}

function renderWebSettings() {
  if (!state.webSettings) return;
  const sourceLabels = {
    webui: "WebUI",
    environment: "服务器环境变量",
    automatic: "监听地址（自动）",
  };
  const form = $("#webSettingsForm");
  const publicOrigin = effectivePublicOrigin();
  form.elements.publicOrigin.value = publicOrigin;
  $("#effectivePublicOrigin").textContent = publicOrigin;
  $("#publicOriginSource").textContent = sourceLabels[state.webSettings.source] || "未知";
  $("#secureCookieStatus").textContent = state.webSettings.cookieSecure ? "已启用" : "未启用";
  $("#resetWebSettingsBtn").disabled = state.webSettings.source !== "webui";

  const warning = $("#securityWarning");
  warning.textContent = state.webSettings.publicAccessWarning
    ? "当前管理面板没有配置 HTTPS 域名，正在通过公网地址直接访问。登录信息和提交的 SSH 凭据可能被链路监听，请尽快配置域名与 HTTPS。"
    : "";
  warning.hidden = !warning.textContent;
}

function shareLinkDisplayName(value) {
  try {
    const fragment = new URL(String(value || "")).hash.slice(1);
    return fragment ? decodeURIComponent(fragment) : "";
  } catch (_error) {
    return "";
  }
}

function subscriptionNodeItem(node, selected) {
  const selectedQuota = selected?.quotaBytes ?? node.quota_bytes;
  const displayName = selected?.displayName || "";
  const currentName = shareLinkDisplayName(node.share_link) || node.server_name;
  return `
    <article class="node-option">
      <input type="checkbox" name="nodeIds" value="${escapeHtml(node.id)}" ${selected ? "checked" : ""} />
      <div>
        <strong>${escapeHtml(node.name)}</strong>
        <small>${escapeHtml(node.server_name)} · ${bytes(node.quota_bytes)} · ${node.enabled ? "启用" : "禁用"}</small>
        <span class="mono">${escapeHtml(node.share_link)}</span>
        <div class="node-option-fields">
          <label>
            节点显示名称
            <input name="displayName:${escapeHtml(node.id)}" type="text" maxlength="128" value="${escapeHtml(displayName)}" placeholder="当前：${escapeHtml(currentName)}" />
          </label>
          <label>
            流量 GB
            <input name="quotaGb:${escapeHtml(node.id)}" type="number" min="0" step="1" value="${escapeHtml(gb(selectedQuota))}" />
          </label>
        </div>
      </div>
    </article>
  `;
}

function subscriptionChainItem(chain, selected) {
  const ready = Boolean(chain.share_link);
  const displayName = selected?.displayName || "";
  const currentName = shareLinkDisplayName(chain.share_link) || chain.name;
  return `
    <article class="node-option ${ready ? "" : "disabled"}">
      <input type="checkbox" name="chainIds" value="${escapeHtml(chain.id)}" ${selected ? "checked" : ""} ${ready ? "" : "disabled"} />
      <div>
        <strong>${escapeHtml(chain.name)}</strong>
        <small>${escapeHtml(chain.path)} · ${ready ? "可加入订阅" : "下发成功后可加入"}</small>
        ${ready ? `<span class="mono">${escapeHtml(chain.share_link)}</span>` : ""}
        <div class="node-option-fields">
          <label>
            代理链显示名称
            <input name="chainDisplayName:${escapeHtml(chain.id)}" type="text" maxlength="128" value="${escapeHtml(displayName)}" placeholder="当前：${escapeHtml(currentName)}" ${ready ? "" : "disabled"} />
          </label>
        </div>
      </div>
    </article>
  `;
}

function closeSubscriptionEdit() {
  $("#subscriptionDialog").close();
  $("#subscriptionForm").reset();
  $("#subscriptionNodeList").innerHTML = "";
}

async function pollJob(jobId) {
  clearTimeout(state.jobTimer);
  state.activeJobId = jobId;
  state.jobLogSeq = 0;
  state.jobLogs = [];
  setSection("logs");

  const tick = async () => {
    try {
      const job = await api(`/api/jobs/${jobId}?after=${state.jobLogSeq}`);
      if (state.activeJobId !== jobId) return;
      state.jobLogs.push(...job.logs);
      state.jobLogs = state.jobLogs.slice(-2000);
      state.jobLogSeq = Number(job.last_log_seq || state.jobLogSeq);
      $("#jobStatus").textContent = job.status;
      $("#jobStatus").className = `badge ${job.status === "success" ? "ok" : job.status === "failed" ? "bad" : "warn"}`;
      $("#jobLog").textContent = state.jobLogs
        .map((entry) => `[${entry.at}] ${entry.line}`)
        .join("\n");
      $("#jobLog").scrollTop = $("#jobLog").scrollHeight;
      if (job.status === "success" || job.status === "failed") {
        state.jobTimer = null;
        await refresh();
        return;
      }
      state.jobTimer = setTimeout(tick, 800);
    } catch (error) {
      if (state.activeJobId !== jobId) return;
      toast(error instanceof Error ? error.message : "任务日志读取失败");
      state.jobTimer = setTimeout(tick, 2000);
    }
  };

  await tick();
}

function syncRealityTargetFields() {
  const isReality = $("#deployProtocol").value === "VLESS + REALITY";
  $("#realityFields").hidden = !isReality;
  const manual = isReality && $("#realityMode").value === "manual";
  $("#realityManualFields").hidden = !manual;
  $("#deployForm").realityDest.required = manual;
}

function bindEvents() {
  $("#realityMode").addEventListener("change", syncRealityTargetFields);
  $("#deployProtocol").addEventListener("change", syncRealityTargetFields);
  syncRealityTargetFields();
  const clientForm = $("#clientForm");
  const clientEditForm = $("#clientEditForm");
  clientForm.elements.neverExpires.addEventListener("change", () => {
    syncNeverExpires(clientForm);
  });
  clientEditForm.elements.neverExpires.addEventListener("change", () => {
    syncNeverExpires(clientEditForm, true);
  });
  syncNeverExpires(clientForm);
  syncNeverExpires(clientEditForm, true);
  $$(".nav-item").forEach((button) => {
    button.addEventListener("click", () => setSection(button.dataset.section));
  });
  $$("[data-section-jump]").forEach((button) => {
    button.addEventListener("click", () => setSection(button.dataset.sectionJump));
  });
  $("#refreshBtn").addEventListener("click", () => refresh().then(() => toast("已刷新")));
  $("#refreshTrafficBtn").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const result = await api("/api/traffic/refresh", { method: "POST", body: "{}" });
      const failed = (result.errors || []).length;
      await refresh();
      toast(
        failed
          ? `已同步 ${result.deployments} 个部署，${failed} 个失败`
          : `已同步 ${result.deployments} 个部署的用量`,
      );
    } catch (error) {
      toast(error instanceof Error ? error.message : "刷新用量失败");
    } finally {
      button.disabled = false;
    }
  });
  $("#healthCheckBtn").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const result = await api("/api/servers/health-check", { method: "POST", body: "{}" });
      await refresh();
      toast(
        `健康检查完成：${result.reachable} 可达 · ${result.authFailed} 认证失败 · ${result.unreachable} 不可达`,
      );
    } catch (error) {
      toast(error instanceof Error ? error.message : "健康检查失败");
    } finally {
      button.disabled = false;
    }
  });
  $("#logoutBtn").addEventListener("click", () => logout());

  $("#webSettingsForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const candidate = String(form.elements.publicOrigin.value || "").trim();
    let parsed;
    try {
      parsed = new URL(candidate);
    } catch {
      return toast("请输入完整的 HTTPS 外部访问地址");
    }
    if (
      parsed.protocol !== "https:" ||
      parsed.username ||
      parsed.password ||
      (parsed.pathname && parsed.pathname !== "/") ||
      parsed.search ||
      parsed.hash
    ) {
      return toast("地址只能包含 HTTPS、域名和可选端口");
    }
    const normalized = parsed.origin;
    if (!confirm(`保存后订阅链接将使用：\n${normalized}\n\n请确认域名解析、HTTPS 和反向代理已经可用。`)) return;
    let settings;
    try {
      settings = await api("/api/settings", {
        method: "PATCH",
        body: JSON.stringify({ publicOrigin: candidate }),
      });
    } catch (error) {
      return toast(error instanceof Error ? error.message : "保存外部访问地址失败");
    }
    state.webSettings = settings;
    renderWebSettings();
    renderDeployments();
    renderSubscriptions();
    renderChains();
    toast("外部访问地址已生效");
    if (settings.publicOrigin !== window.location.origin && confirm("现在通过新的外部地址重新打开并登录？")) {
      window.location.href = settings.publicOrigin;
    }
  });

  $("#resetWebSettingsBtn").addEventListener("click", async () => {
    if (!confirm("恢复 .env 或自动检测的服务器配置？")) return;
    let settings;
    try {
      settings = await api("/api/settings", {
        method: "PATCH",
        body: JSON.stringify({ publicOrigin: "" }),
      });
    } catch (error) {
      return toast(error instanceof Error ? error.message : "恢复服务器配置失败");
    }
    state.webSettings = settings;
    renderWebSettings();
    renderDeployments();
    renderSubscriptions();
    renderChains();
    toast("已恢复服务器配置");
  });

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
    const server = state.servers.find((item) => item.id === data.serverId);
    if (!server) return toast("服务器不存在，请刷新后重试");
    const existingDeployment = state.deployments.find(
      (item) => item.server_id === server.id && item.install_method === "native",
    );
    if (existingDeployment) {
      return toast("该服务器已有原生 3x-ui 部署记录，请先删除旧部署后再创建");
    }
    if (server.status !== "reachable") {
      return toast("请先在服务器页面测试 SSH 连接");
    }
    if (!server.host_key_trusted) {
      return toast(
        server.host_key_fingerprint
          ? "请先在服务器页面核验并信任 SSH 主机指纹"
          : "请先在服务器页面测试连接并核验 SSH 主机指纹",
      );
    }

    const button = form.querySelector('button[type="submit"]');
    const originalText = button.textContent;
    button.disabled = true;
    button.textContent = "正在创建部署…";
    try {
      const result = await api(`/api/servers/${data.serverId}/deploy`, {
        method: "POST",
        body: JSON.stringify(data),
      });
      toast("部署任务已创建");
      await pollJob(result.job.id);
    } catch (error) {
      toast(error instanceof Error ? error.message : "创建部署失败");
    } finally {
      button.disabled = false;
      button.textContent = originalText;
    }
  });

  $("#clientForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = formData(form);
    if (!data.deploymentId) return toast("请选择节点");
    const deploymentId = data.deploymentId;
    await api(`/api/deployments/${data.deploymentId}/clients`, {
      method: "POST",
      body: JSON.stringify(data),
    });
    form.reset();
    syncNeverExpires(form);
    await refresh();
    form.elements.deploymentId.value = deploymentId;
    form.elements.name.focus();
    toast("用户已创建，可继续在该节点添加其他用户");
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
    if (!chainPortsValid()) return toast("请为每个节点填写 1–65535 的对等映射链路端口");
    await api("/api/chains", {
      method: "POST",
      body: JSON.stringify({
        name: data.name,
        deploymentIds: state.chainDraft,
        inboundPorts: chainInboundPorts(),
        linkProtocols: chainLinkProtocols(),
      }),
    });
    state.chainDraft = [];
    state.chainProtocolDraft = {};
    state.chainPortDraft = {};
    form.reset();
    toast("代理链已保存");
    await refresh();
  });

  $("#clientEditForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.currentTarget;
    const data = formData(form);
    const client = state.clients.find((item) => item.id === data.id);
    if (!client) return toast("用户不存在");
    await api(`/api/clients/${data.id}`, {
      method: "PATCH",
      body: JSON.stringify({
        name: data.name,
        quotaGb: data.quotaGb,
        trafficResetDays: data.trafficResetDays,
        expiresAt: data.expiresAt,
        neverExpires: data.neverExpires,
        enabled: Boolean(client.enabled),
      }),
    });
    closeClientEdit();
    toast("用户已更新");
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
        displayName: form.elements[`displayName:${input.value}`]?.value || "",
      }));
    const chains = Array.from(form.querySelectorAll('input[name="chainIds"]:checked'))
      .map((input) => ({
        chainId: input.value,
        displayName: form.elements[`chainDisplayName:${input.value}`]?.value || "",
      }));
    await api(`/api/subscriptions/${subscriptionId}`, {
      method: "PATCH",
      body: JSON.stringify({
        name: form.elements.name.value,
        nodes,
        chains,
      }),
    });
    closeSubscriptionEdit();
    toast("订阅内容已更新");
    await refresh();
  });

  document.body.addEventListener("dragstart", (event) => {
    if (event.target.closest("input, select, button")) {
      event.preventDefault();
      return;
    }
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

  document.body.addEventListener("input", (event) => {
    const input = event.target.closest("[data-chain-port]");
    if (!input) return;
    state.chainPortDraft[input.dataset.deploymentId] = input.value.trim();
    const selected = state.chainDraft
      .map((deploymentId) => state.deployments.find((deployment) => deployment.id === deploymentId))
      .filter(Boolean);
    $("#chainPreview").textContent = chainPreviewText(selected);
    updateChainSubmitState();
  });

  document.body.addEventListener("click", async (event) => {
    const target = event.target.closest("button");
    if (!target) return;

    if (target.dataset.closeClientEdit !== undefined) {
      closeClientEdit();
    }

    if (target.dataset.closeQr !== undefined) {
      closeQr();
    }

    if (target.dataset.qr !== undefined) {
      openQr(target.dataset.qr, target.dataset.qrTitle);
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

    if (target.dataset.addUser) {
      setSection("clients");
      $("#clientDeploymentSelect").value = target.dataset.addUser;
      $("#clientForm").elements.name.focus();
    }

    if (target.dataset.deleteServer) {
      const server = state.servers.find((item) => item.id === target.dataset.deleteServer);
      if (
        !confirm(
          `删除服务器 ${server?.name || ""}？会尝试卸载远端 3x-ui 并删除本地记录。若远端不可达，仍会删除本地记录，远端可能需手工清理。`,
        )
      ) {
        return;
      }
      const result = await api(`/api/servers/${target.dataset.deleteServer}`, {
        method: "DELETE",
      });
      toast(
        result.remoteCleanupOk === false
          ? "服务器本地记录已删除，远端清理失败，请检查残留"
          : "服务器已删除",
      );
      await refresh();
    }

    if (target.dataset.deleteDeployment) {
      const deployment = state.deployments.find((item) => item.id === target.dataset.deleteDeployment);
      if (
        !confirm(
          `删除部署 ${deployment?.server_name || ""}？会尝试清理远端部署内容并删除本地记录。若远端不可达，仍会删除本地记录，远端可能需手工清理。`,
        )
      ) {
        return;
      }
      const result = await api(`/api/deployments/${target.dataset.deleteDeployment}`, {
        method: "DELETE",
      });
      toast(
        result.remoteCleanupOk === false
          ? "部署本地记录已删除，远端清理失败，请检查残留"
          : "部署已删除",
      );
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
      try {
        await api(`/api/clients/${target.dataset.resetClient}/reset`, {
          method: "POST",
          body: "{}",
        });
        toast("本地与 3x-ui 流量已重置");
        await refresh();
      } catch (error) {
        toast(error instanceof Error ? error.message : "重置流量失败");
      }
    }

    if (target.dataset.toggleClient) {
      const client = state.clients.find((item) => item.id === target.dataset.toggleClient);
      await api(`/api/clients/${target.dataset.toggleClient}`, {
        method: "PATCH",
        body: JSON.stringify({
          name: client.name,
          quotaGb: gb(client.quota_bytes),
          expiresAt: client.expires_at,
          neverExpires: !client.expires_at,
          enabled: Number(target.dataset.enabled) === 1,
        }),
      });
      toast("用户状态已更新");
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
