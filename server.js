import express from "express";
import path from "path";
import { fileURLToPath } from "url";

import { getState, updateState, normalizeState, saveState } from "./lib/store.js";
import { parseSubscription, summarizeNode } from "./lib/parse.js";
import {
  startV2Ray,
  stopV2Ray,
  ensureStoppedOnExit,
  getRuntimeStatus,
  refreshRuntimeStatus
} from "./lib/v2ray.js";
import { measureNodes } from "./lib/latency.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 22007;
const latencyCache = new Map();

app.use(express.json({ limit: "1mb" }));

function parseCookies(req) {
  const header = req.headers.cookie || "";
  return header.split(";").reduce((acc, part) => {
    const [key, ...rest] = part.trim().split("=");
    if (!key) return acc;
    acc[key] = decodeURIComponent(rest.join("="));
    return acc;
  }, {});
}

async function requireToken(req, res, next) {
  try {
    const state = normalizeState(await getState());
    const accessToken = state.settings?.accessToken || "";
    if (!accessToken) {
      return next();
    }
    const queryToken = typeof req.query?.token === "string" ? req.query.token : "";
    const headerToken = req.get("x-access-token") || "";
    const cookies = parseCookies(req);
    const cookieToken = cookies.s5route_token || "";
    const provided = queryToken || headerToken || cookieToken;

    if (provided === accessToken) {
      if (queryToken && cookieToken !== accessToken) {
        res.setHeader(
          "Set-Cookie",
          `s5route_token=${encodeURIComponent(accessToken)}; Path=/; HttpOnly; SameSite=Lax`
        );
      }
      return next();
    }

    if (req.path.startsWith("/api/")) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    return res
      .status(401)
      .send("<h1>Unauthorized</h1><p>Access token required.</p>");
  } catch (err) {
    return next(err);
  }
}

app.use(requireToken);
app.use(express.static(path.join(__dirname, "public")));

function sanitizeState(state) {
  const nodes = Object.values(state.nodes || {}).map(summarizeNode);
  const runtime = getRuntimeStatus();
  const settings = { ...(state.settings || {}) };
  delete settings.accessToken;
  return {
    settings,
    subscriptions: state.subscriptions,
    nodes,
    selectedNodeId: state.selectedNodeId,
    v2ray: { ...state.v2ray, ...runtime }
  };
}

async function fetchSubscription(url) {
  const response = await fetch(url, {
    headers: {
      "User-Agent": "s5route/0.1"
    }
  });
  if (!response.ok) {
    throw new Error(`Subscription fetch failed (${response.status})`);
  }
  return (await response.text()).trim();
}

async function refreshSubscription(state, sub) {
  try {
    const raw = await fetchSubscription(sub.url);
    const nodes = parseSubscription(raw, sub.id, sub.name || sub.url);

    for (const [id, node] of Object.entries(state.nodes)) {
      if (node.sourceId === sub.id) {
        delete state.nodes[id];
      }
    }

    for (const node of nodes) {
      state.nodes[node.id] = node;
    }

    sub.lastUpdated = new Date().toISOString();
    sub.count = nodes.length;
    sub.lastError = null;
  } catch (err) {
    sub.lastError = err.message || "Failed to refresh";
  }
}

app.get("/api/state", async (req, res) => {
  const state = normalizeState(await getState());
  await refreshRuntimeStatus(state);
  await saveState(state);
  res.json(sanitizeState(state));
});

app.get("/api/latency", async (req, res) => {
  const state = normalizeState(await getState());
  const nodes = Object.values(state.nodes || {});
  const force = req.query?.force === "1";
  const latencies = await measureNodes(nodes, {
    cache: latencyCache,
    ttlMs: force ? 0 : undefined
  });
  res.json({ latencies });
});

app.post("/api/settings", async (req, res) => {
  const { socksPort, listen, accessToken } = req.body || {};
  const state = await updateState(async (draft) => {
    draft = normalizeState(draft);
    if (Number.isInteger(socksPort) && socksPort > 0 && socksPort < 65536) {
      draft.settings.socksPort = socksPort;
    }
    if (typeof listen === "string" && listen.trim()) {
      draft.settings.listen = listen.trim();
    }
    if (typeof accessToken === "string") {
      draft.settings.accessToken = accessToken.trim();
    }
    return draft;
  });
  if (typeof accessToken === "string" && accessToken.trim()) {
    res.setHeader(
      "Set-Cookie",
      `s5route_token=${encodeURIComponent(accessToken.trim())}; Path=/; HttpOnly; SameSite=Lax`
    );
  }
  res.json(sanitizeState(state));
});

app.post("/api/subscriptions", async (req, res) => {
  const { url, name } = req.body || {};
  if (!url || typeof url !== "string") {
    res.status(400).json({ error: "url required" });
    return;
  }

  const state = await updateState(async (draft) => {
    draft = normalizeState(draft);
    const id = cryptoRandomId();
    const sub = {
      id,
      url: url.trim(),
      name: typeof name === "string" ? name.trim() : "",
      lastUpdated: null,
      count: 0,
      lastError: null
    };
    draft.subscriptions.push(sub);
    await refreshSubscription(draft, sub);
    return draft;
  });

  res.json(sanitizeState(state));
});

app.post("/api/subscriptions/refresh", async (req, res) => {
  const state = await updateState(async (draft) => {
    draft = normalizeState(draft);
    for (const sub of draft.subscriptions) {
      await refreshSubscription(draft, sub);
    }
    return draft;
  });
  res.json(sanitizeState(state));
});

app.delete("/api/subscriptions/:id", async (req, res) => {
  const { id } = req.params;
  const state = await updateState(async (draft) => {
    draft = normalizeState(draft);
    draft.subscriptions = draft.subscriptions.filter((sub) => sub.id !== id);
    for (const [nodeId, node] of Object.entries(draft.nodes)) {
      if (node.sourceId === id) {
        delete draft.nodes[nodeId];
      }
    }
    if (draft.selectedNodeId && !draft.nodes[draft.selectedNodeId]) {
      draft.selectedNodeId = null;
    }
    return draft;
  });
  res.json(sanitizeState(state));
});

app.post("/api/select", async (req, res) => {
  const { nodeId } = req.body || {};
  const state = await updateState(async (draft) => {
    draft = normalizeState(draft);
    if (!draft.nodes[nodeId]) {
      return draft;
    }
    draft.selectedNodeId = nodeId;
    await startV2Ray(draft, draft.nodes[nodeId]);
    return draft;
  });

  await refreshRuntimeStatus(state);
  await saveState(state);
  res.json(sanitizeState(state));
});

app.post("/api/v2ray/start", async (req, res) => {
  const state = await updateState(async (draft) => {
    draft = normalizeState(draft);
    const node = draft.selectedNodeId ? draft.nodes[draft.selectedNodeId] : null;
    await startV2Ray(draft, node);
    return draft;
  });
  await refreshRuntimeStatus(state);
  await saveState(state);
  res.json(sanitizeState(state));
});

app.post("/api/v2ray/stop", async (req, res) => {
  const state = await updateState(async (draft) => {
    draft = normalizeState(draft);
    await stopV2Ray(draft);
    return draft;
  });
  await refreshRuntimeStatus(state);
  await saveState(state);
  res.json(sanitizeState(state));
});

app.get("/api/health", (req, res) => {
  res.json({ ok: true });
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

function cryptoRandomId() {
  return Math.random().toString(36).slice(2, 10) + Date.now().toString(36);
}

ensureStoppedOnExit();

app.listen(PORT, () => {
  console.log(`s5route listening on http://localhost:${PORT}`);
});
