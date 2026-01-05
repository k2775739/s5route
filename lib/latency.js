import net from "net";

const DEFAULT_TIMEOUT_MS = 3000;
const DEFAULT_CONCURRENCY = 8;

function getTargetFromOutbound(outbound) {
  if (!outbound || !outbound.settings) {
    return null;
  }
  if (outbound.protocol === "trojan" || outbound.protocol === "shadowsocks") {
    const server = outbound.settings.servers?.[0];
    if (!server) return null;
    return { host: server.address, port: Number(server.port) };
  }
  const vnext = outbound.settings.vnext?.[0];
  if (!vnext) {
    return null;
  }
  return { host: vnext.address, port: Number(vnext.port) };
}

function tcpPing(host, port, timeoutMs) {
  return new Promise((resolve) => {
    if (!host || !port) {
      resolve({ ms: null, error: "invalid" });
      return;
    }
    const start = Date.now();
    const socket = net.connect({ host, port });
    let done = false;

    const finish = (result) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(result);
    };

    socket.setTimeout(timeoutMs);
    socket.on("connect", () => finish({ ms: Date.now() - start, error: null }));
    socket.on("timeout", () => finish({ ms: null, error: "timeout" }));
    socket.on("error", (err) => finish({ ms: null, error: err.code || "error" }));
  });
}

async function runWithLimit(tasks, limit) {
  const results = new Array(tasks.length);
  let index = 0;

  const workers = new Array(Math.min(limit, tasks.length)).fill(0).map(async () => {
    while (index < tasks.length) {
      const current = index++;
      results[current] = await tasks[current]();
    }
  });

  await Promise.all(workers);
  return results;
}

export async function measureNodes(nodes, options = {}) {
  const {
    timeoutMs = DEFAULT_TIMEOUT_MS,
    concurrency = DEFAULT_CONCURRENCY,
    cache = null,
    ttlMs = 60_000
  } = options;

  const now = Date.now();
  const tasks = nodes.map((node) => async () => {
    const cached = cache?.get(node.id);
    if (cached && now - cached.updatedAtMs < ttlMs) {
      return { id: node.id, result: cached };
    }

    const target = getTargetFromOutbound(node.outbound);
    const ping = await tcpPing(target?.host, target?.port, timeoutMs);
    const entry = {
      ms: ping.ms,
      error: ping.error,
      host: target?.host || "",
      port: target?.port || 0,
      updatedAt: new Date().toISOString(),
      updatedAtMs: Date.now()
    };
    if (cache) {
      cache.set(node.id, entry);
    }
    return { id: node.id, result: entry };
  });

  const settled = await runWithLimit(tasks, concurrency);
  return settled.reduce((acc, item) => {
    if (item) {
      acc[item.id] = item.result;
    }
    return acc;
  }, {});
}
