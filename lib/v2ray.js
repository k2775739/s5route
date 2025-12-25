import fs from "fs/promises";
import path from "path";
import { spawn } from "child_process";

const dataDir = path.resolve("data");
const configPath = path.join(dataDir, "v2ray.generated.json");
const logPath = path.join(dataDir, "v2ray.log");

let currentProcess = null;
const runtimeStatus = {
  running: false,
  pid: null,
  lastError: null,
  lastStarted: null
};

const isLinux = process.platform === "linux";

async function writeConfig(config) {
  await fs.mkdir(dataDir, { recursive: true });
  await fs.writeFile(configPath, JSON.stringify(config, null, 2), "utf8");
}

export function buildConfig(state, node) {
  const inboundTag = "socks-in";
  const outboundTag = "proxy";

  return {
    log: {
      loglevel: "error"
    },
    inbounds: [
      {
        tag: inboundTag,
        listen: state.settings.listen,
        port: state.settings.socksPort,
        protocol: "socks",
        settings: {
          udp: true
        }
      }
    ],
    outbounds: [
      {
        tag: outboundTag,
        ...node.outbound
      },
      {
        tag: "direct",
        protocol: "freedom"
      },
      {
        tag: "block",
        protocol: "blackhole"
      }
    ],
    routing: {
      rules: [
        {
          type: "field",
          inboundTag: [inboundTag],
          outboundTag
        }
      ]
    }
  };
}

function stopProcess() {
  if (currentProcess && !currentProcess.killed) {
    currentProcess.kill("SIGTERM");
  }
  currentProcess = null;
  runtimeStatus.running = false;
  runtimeStatus.pid = null;
}

export async function stopV2Ray(state) {
  stopProcess();
  state.v2ray.running = false;
  state.v2ray.pid = null;
  return state;
}

export async function startV2Ray(state, node) {
  if (!node) {
    state.v2ray.lastError = "No node selected";
    state.v2ray.running = false;
    state.v2ray.pid = null;
    runtimeStatus.lastError = state.v2ray.lastError;
    return state;
  }

  const config = buildConfig(state, node);
  await writeConfig(config);
  stopProcess();

  const args = Array.isArray(state.settings.v2rayArgs)
    ? state.settings.v2rayArgs
    : ["run", "-c", "data/v2ray.generated.json"];

  return new Promise((resolve) => {
    try {
      const child = spawn(state.settings.v2rayBin, args, {
        stdio: ["ignore", "pipe", "pipe"]
      });

      currentProcess = child;
      state.v2ray.running = true;
      state.v2ray.pid = child.pid;
      state.v2ray.lastStarted = new Date().toISOString();
      state.v2ray.lastError = null;
      runtimeStatus.running = true;
      runtimeStatus.pid = child.pid;
      runtimeStatus.lastStarted = state.v2ray.lastStarted;
      runtimeStatus.lastError = null;

      child.stdout?.on("data", async (chunk) => {
        await fs.appendFile(logPath, chunk.toString("utf8"));
      });
      child.stderr?.on("data", async (chunk) => {
        await fs.appendFile(logPath, chunk.toString("utf8"));
      });
      child.on("exit", (code, signal) => {
        if (currentProcess === child) {
          currentProcess = null;
        }
        state.v2ray.running = false;
        state.v2ray.pid = null;
        state.v2ray.lastError = code === 0 ? null : `Exited (${signal || code})`;
        runtimeStatus.running = false;
        runtimeStatus.pid = null;
        runtimeStatus.lastError = state.v2ray.lastError;
      });

      resolve(state);
    } catch (err) {
      state.v2ray.lastError = err.message || "Failed to start v2ray";
      state.v2ray.running = false;
      state.v2ray.pid = null;
      runtimeStatus.lastError = state.v2ray.lastError;
      runtimeStatus.running = false;
      runtimeStatus.pid = null;
      resolve(state);
    }
  });
}

export async function ensureStoppedOnExit() {
  process.on("SIGINT", () => {
    stopProcess();
    process.exit(0);
  });
  process.on("SIGTERM", () => {
    stopProcess();
    process.exit(0);
  });
}

export function getConfigPath() {
  return configPath;
}

export function getRuntimeStatus() {
  return { ...runtimeStatus };
}

function isPidAlive(pid) {
  if (!pid) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

async function readCmdline(pid) {
  if (!isLinux || !pid) {
    return "";
  }
  try {
    const raw = await fs.readFile(`/proc/${pid}/cmdline`, "utf8");
    return raw.replace(/\0/g, " ").trim();
  } catch {
    return "";
  }
}

function resolveConfigCandidates(state) {
  const candidates = new Set([configPath]);
  const args = state.settings?.v2rayArgs;
  if (Array.isArray(args)) {
    const idx = args.findIndex((arg) => ["-c", "-config", "--config"].includes(arg));
    if (idx >= 0 && args[idx + 1]) {
      candidates.add(args[idx + 1]);
      candidates.add(path.resolve(args[idx + 1]));
    }
  }
  return [...candidates];
}

async function cmdlineMatchesConfig(pid, candidates) {
  const cmdline = await readCmdline(pid);
  if (!cmdline) {
    return false;
  }
  return candidates.some((candidate) => cmdline.includes(candidate));
}

async function findPidByConfig(candidates) {
  if (!isLinux) {
    return null;
  }
  try {
    const entries = await fs.readdir("/proc");
    for (const entry of entries) {
      if (!/^\d+$/.test(entry)) {
        continue;
      }
      const pid = Number.parseInt(entry, 10);
      const match = await cmdlineMatchesConfig(pid, candidates);
      if (match) {
        return pid;
      }
    }
  } catch {
    return null;
  }
  return null;
}

export async function refreshRuntimeStatus(state) {
  const pid = Number(state?.v2ray?.pid || 0);
  const candidates = resolveConfigCandidates(state);
  let running = false;
  let matchedPid = null;

  if (pid && isPidAlive(pid)) {
    if (await cmdlineMatchesConfig(pid, candidates)) {
      running = true;
      matchedPid = pid;
    }
  }

  if (!running) {
    const foundPid = await findPidByConfig(candidates);
    if (foundPid) {
      running = true;
      matchedPid = foundPid;
    }
  }

  runtimeStatus.running = running;
  runtimeStatus.pid = matchedPid;
  if (running) {
    runtimeStatus.lastError = null;
  }

  if (state?.v2ray) {
    state.v2ray.running = running;
    state.v2ray.pid = matchedPid;
    if (running) {
      state.v2ray.lastError = null;
    }
  }

  return state;
}
