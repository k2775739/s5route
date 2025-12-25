const state = {
  data: null,
  filter: ""
};

const qs = (sel) => document.querySelector(sel);

function toast(message) {
  const node = qs("#toast");
  node.textContent = message;
  node.classList.add("show");
  setTimeout(() => node.classList.remove("show"), 2200);
}

async function api(path, options) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    throw new Error(payload.error || "请求失败");
  }
  return response.json();
}

function render() {
  if (!state.data) return;

  const { settings, subscriptions, nodes, selectedNodeId, v2ray } = state.data;
  const selectedNode = nodes.find((node) => node.id === selectedNodeId);

  qs("#currentNode").textContent = selectedNode ? selectedNode.name : "未选择";
  qs("#v2Status").textContent = v2ray.running ? `运行中 (PID ${v2ray.pid || "-"})` : "停止";
  qs("#socksEndpoint").textContent = `${settings.listen}:${settings.socksPort}`;
  qs("#lastStarted").textContent = v2ray.lastStarted ? new Date(v2ray.lastStarted).toLocaleString() : "-";

  const toggleBtn = qs("#toggleV2");
  if (toggleBtn) {
    toggleBtn.textContent = v2ray.running ? "关闭 V2Ray" : "启动 V2Ray";
  }

  const settingsForm = qs("#settingsForm");
  settingsForm.listen.value = settings.listen || "0.0.0.0";
  settingsForm.socksPort.value = settings.socksPort || 1080;
  if (settingsForm.accessToken) {
    settingsForm.accessToken.value = "";
  }

  renderSubscriptions(subscriptions);
  renderNodes(nodes, selectedNodeId);
}

function renderSubscriptions(subscriptions) {
  const container = qs("#subsList");
  container.innerHTML = "";

  if (!subscriptions.length) {
    container.innerHTML = "<p class=\"label\">暂无订阅</p>";
    return;
  }

  subscriptions.forEach((sub) => {
    const item = document.createElement("div");
    item.className = "list-item";

    const meta = document.createElement("div");
    meta.className = "meta";
    meta.innerHTML = `
      <strong>${sub.name || sub.url}</strong>
      <span class="label">${sub.count || 0} 节点 · ${sub.lastUpdated ? new Date(sub.lastUpdated).toLocaleString() : "未刷新"}</span>
      ${sub.lastError ? `<span class="label" style="color:#b91c1c;">${sub.lastError}</span>` : ""}
    `;

    const actions = document.createElement("div");
    actions.className = "actions";

    const refreshBtn = document.createElement("button");
    refreshBtn.className = "ghost";
    refreshBtn.textContent = "刷新";
    refreshBtn.addEventListener("click", async () => {
      try {
        await refreshAll();
      } catch (err) {
        toast(err.message);
      }
    });

    const removeBtn = document.createElement("button");
    removeBtn.className = "ghost";
    removeBtn.textContent = "删除";
    removeBtn.addEventListener("click", async () => {
      try {
        state.data = await api(`/api/subscriptions/${sub.id}`, { method: "DELETE" });
        render();
      } catch (err) {
        toast(err.message);
      }
    });

    actions.append(refreshBtn, removeBtn);
    item.append(meta, actions);
    container.append(item);
  });
}

function renderNodes(nodes, selectedNodeId) {
  const container = qs("#nodesList");
  container.innerHTML = "";

  const filtered = nodes.filter((node) =>
    (node.name || "").toLowerCase().includes(state.filter.toLowerCase())
  );

  if (!filtered.length) {
    container.innerHTML = "<p class=\"label\">暂无节点</p>";
    return;
  }

  filtered.forEach((node) => {
    const item = document.createElement("div");
    item.className = "list-item node-item" + (node.id === selectedNodeId ? " selected" : "");
    item.tabIndex = 0;
    item.setAttribute("role", "button");

    const meta = document.createElement("div");
    meta.className = "meta";
    meta.innerHTML = `
      <div class="node-main">
        <strong class="node-title">${node.name}</strong>
        <span class="node-sub">${node.sourceName || ""}</span>
      </div>
      <div class="node-tags">
        <span class="badge">${node.protocol.toUpperCase()}</span>
        ${node.id === selectedNodeId ? `<span class="badge selected-badge">已选择</span>` : ""}
      </div>
    `;
    const selectNode = async () => {
      if (node.id === selectedNodeId) {
        return;
      }
      try {
        state.data = await api("/api/select", {
          method: "POST",
          body: JSON.stringify({ nodeId: node.id })
        });
        render();
      } catch (err) {
        toast(err.message);
      }
    };

    item.addEventListener("click", selectNode);
    item.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectNode();
      }
    });

    item.append(meta);
    container.append(item);
  });
}

async function refreshAll() {
  state.data = await api("/api/subscriptions/refresh", { method: "POST" });
  render();
}

async function init() {
  state.data = await api("/api/state");
  render();

  qs("#subForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.target;
    const payload = {
      name: form.name.value.trim(),
      url: form.url.value.trim()
    };
    if (!payload.url) return;
    try {
      state.data = await api("/api/subscriptions", {
        method: "POST",
        body: JSON.stringify(payload)
      });
      form.reset();
      render();
      toast("订阅已添加");
    } catch (err) {
      toast(err.message);
    }
  });

  qs("#settingsForm").addEventListener("submit", async (event) => {
    event.preventDefault();
    const form = event.target;
    const socksPort = Number.parseInt(form.socksPort.value, 10);
    const accessToken = form.accessToken?.value?.trim();

    try {
      const payload = {
        listen: form.listen.value.trim(),
        socksPort: Number.isFinite(socksPort) ? socksPort : undefined
      };
      if (accessToken) {
        payload.accessToken = accessToken;
      }
      state.data = await api("/api/settings", {
        method: "POST",
        body: JSON.stringify(payload)
      });
      render();
      toast("设置已保存");
    } catch (err) {
      toast(err.message);
    }
  });

  qs("#refreshAll").addEventListener("click", async () => {
    try {
      await refreshAll();
      toast("订阅已刷新");
    } catch (err) {
      toast(err.message);
    }
  });

  qs("#toggleV2").addEventListener("click", async () => {
    try {
      if (state.data?.v2ray?.running) {
        state.data = await api("/api/v2ray/stop", { method: "POST" });
        toast("V2Ray 已停止");
      } else {
        state.data = await api("/api/v2ray/start", { method: "POST" });
        toast("V2Ray 已启动");
      }
      render();
    } catch (err) {
      toast(err.message);
    }
  });

  qs("#stopV2").addEventListener("click", async () => {
    try {
      state.data = await api("/api/v2ray/stop", { method: "POST" });
      render();
      toast("V2Ray 已停止");
    } catch (err) {
      toast(err.message);
    }
  });

  qs("#nodeSearch").addEventListener("input", (event) => {
    state.filter = event.target.value || "";
    render();
  });
}

init().catch((err) => {
  console.error(err);
  toast("初始化失败");
});
