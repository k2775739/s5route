import fs from "fs/promises";
import path from "path";

const dataDir = path.resolve("data");
const statePath = path.join(dataDir, "state.json");

const defaultState = {
  settings: {
    listen: "0.0.0.0",
    socksPort: 1080,
    v2rayBin: "/usr/local/bin/v2ray",
    v2rayArgs: ["run", "-c", "data/v2ray.generated.json"],
    accessToken: ""
  },
  subscriptions: [],
  nodes: {},
  selectedNodeId: null,
  v2ray: {
    running: false,
    pid: null,
    lastError: null,
    lastStarted: null
  }
};

async function ensureDataDir() {
  await fs.mkdir(dataDir, { recursive: true });
}

export async function getState() {
  await ensureDataDir();
  try {
    const raw = await fs.readFile(statePath, "utf8");
    return JSON.parse(raw);
  } catch (err) {
    if (err.code !== "ENOENT") {
      throw err;
    }
    await saveState(defaultState);
    return JSON.parse(JSON.stringify(defaultState));
  }
}

export async function saveState(state) {
  await ensureDataDir();
  const next = JSON.stringify(state, null, 2);
  await fs.writeFile(statePath, next, "utf8");
}

export async function updateState(mutator) {
  const state = await getState();
  const result = await mutator(state);
  if (result && typeof result === "object") {
    await saveState(result);
    return result;
  }
  await saveState(state);
  return state;
}

export function normalizeState(state) {
  return {
    ...defaultState,
    ...state,
    settings: { ...defaultState.settings, ...(state.settings || {}) },
    v2ray: { ...defaultState.v2ray, ...(state.v2ray || {}) },
    subscriptions: Array.isArray(state.subscriptions) ? state.subscriptions : [],
    nodes: state.nodes || {}
  };
}
