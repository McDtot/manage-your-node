const state = {
  summary: null,
  servers: [],
  deployments: [],
  subscriptions: [],
  clients: [],
  activeJobId: null,
  jobTimer: null,
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "请求失败");
  }
  return data;
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
  $$(".section").forEach((section) => {
    section.classList.toggle("is-active", section.id === id);
  });
  $$(".nav-item").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.section === id);
  });
  $("#topAddServerBtn").hidden = id !== "servers";
}

function statusBadge(status) {
  const map = {
    ready: "ok",
    reachable: "ok",
    enabled: "ok",
    success: "ok",
    provisioning: "warn",
    running: "warn",
    auth_failed: "bad",
    unreachable: "bad",
    disabled: "bad",
    failed: "bad",
  };
  return `<span class="badge ${map[status] || ""}">${status || "new"}</span>`;
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
  const [summary, servers, deployments, subscriptions, clients] = await Promise.all([
    api("/api/summary"),
    api("/api/servers"),
    api("/api/deployments"),
    api("/api/subscriptions"),
    api("/api/clients"),
  ]);
  state.summary = summary;
  state.servers = servers.servers;
  state.deployments = deployments.deployments;
  state.subscriptions = subscriptions.subscriptions;
  state.clients = clients.clients;
  render();
}

function render() {
  renderSummary();
  renderServers();
  renderDeployments();
  renderSubscriptions();
  renderClients();
  renderSelects();
  $("#statusLine").textContent = `${state.servers.length} 台服务器，${state.deployments.length} 个部署，${state.subscriptions.length} 条订阅，${state.clients.length} 个客户端`;
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
      <div class="item-actions">
        <button class="secondary" data-test-server="${server.id}">测试连接</button>
        <button class="primary" data-deploy-server="${server.id}">部署</button>
        ${options.allowDelete ? `<button class="ghost" data-delete-server="${server.id}">删除</button>` : ""}
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
      <div class="meta">面板：<span class="mono">${escapeHtml(deployment.panel_url || `${deployment.host}:${deployment.panel_port}${deployment.panel_path}`)}</span></div>
      <div class="meta">账号：<span class="mono">${escapeHtml(deployment.panel_username)}</span> / <span class="mono">${escapeHtml(deployment.panel_password || "")}</span></div>
      <div class="meta">入站 ID：<span class="mono">${escapeHtml(deployment.xui_inbound_id || "未同步")}</span></div>
      <div class="meta">默认订阅：<span class="mono">${escapeHtml(subscriptionUrl)}</span></div>
      <div class="item-actions">
        <button class="secondary" data-copy="${escapeHtml(deployment.panel_url || "")}">复制面板</button>
        <button class="secondary" data-copy="${escapeHtml(deployment.panel_password || "")}">复制密码</button>
        <button class="secondary" data-copy="${escapeHtml(deployment.api_token || "")}">复制 Token</button>
        <button class="ghost" data-section-jump="subscriptions">管理订阅</button>
        ${options.allowDelete ? `<button class="ghost" data-delete-deployment="${deployment.id}">删除</button>` : ""}
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
        <button class="ghost" data-delete-subscription="${subscription.id}">删除</button>
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

function bindEvents() {
  $$(".nav-item").forEach((button) => {
    button.addEventListener("click", () => setSection(button.dataset.section));
  });
  $$("[data-section-jump]").forEach((button) => {
    button.addEventListener("click", () => setSection(button.dataset.sectionJump));
  });
  $("#refreshBtn").addEventListener("click", () => refresh().then(() => toast("已刷新")));

  $("#serverForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    await api("/api/servers", {
      method: "POST",
      body: JSON.stringify(formData(event.currentTarget)),
    });
    event.currentTarget.reset();
    event.currentTarget.sshPort.value = 22;
    event.currentTarget.sshUser.value = "root";
    toast("服务器已保存");
    await refresh();
  });

  $("#deployForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = formData(event.currentTarget);
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
    const data = formData(event.currentTarget);
    if (!data.deploymentId) return toast("请选择部署");
    await api(`/api/deployments/${data.deploymentId}/clients`, {
      method: "POST",
      body: JSON.stringify(data),
    });
    event.currentTarget.reset();
    toast("客户端已创建");
    await refresh();
  });

  $("#subscriptionCreateForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = formData(event.currentTarget);
    const subscription = await api("/api/subscriptions", {
      method: "POST",
      body: JSON.stringify(data),
    });
    event.currentTarget.reset();
    toast("订阅已创建");
    await refresh();
    await openSubscriptionEdit(subscription.id);
  });

  $("#clientEditForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = formData(event.currentTarget);
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
refresh().catch((error) => toast(error.message));
