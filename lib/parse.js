import crypto from "crypto";

const SUPPORTED_PREFIXES = ["vmess://", "vless://", "trojan://", "ss://"];

function toSafeBase64(input) {
  return input.replace(/-/g, "+").replace(/_/g, "/");
}

function normalizeBase64(input) {
  const safe = toSafeBase64(input.trim());
  const pad = safe.length % 4;
  if (pad === 0) {
    return safe;
  }
  return safe + "=".repeat(4 - pad);
}

function decodeBase64(input) {
  try {
    return Buffer.from(normalizeBase64(input), "base64").toString("utf8");
  } catch {
    return "";
  }
}

function startsWithSupportedPrefix(value) {
  return SUPPORTED_PREFIXES.some((prefix) => value.startsWith(prefix));
}

function maybeDecodeLine(line) {
  if (startsWithSupportedPrefix(line)) {
    return line;
  }
  const decoded = decodeBase64(line);
  if (decoded && startsWithSupportedPrefix(decoded.trim())) {
    return decoded.trim();
  }
  return line;
}

function maybeDecodeSubscription(raw) {
  const trimmed = raw.trim();
  if (!trimmed) {
    return "";
  }
  if (SUPPORTED_PREFIXES.some((prefix) => trimmed.includes(prefix))) {
    return trimmed;
  }
  const lines = parseLines(trimmed);
  if (lines.length > 1) {
    for (const line of lines) {
      const decodedLine = decodeBase64(line);
      if (decodedLine && startsWithSupportedPrefix(decodedLine.trim())) {
        return trimmed;
      }
    }
  }
  const decoded = decodeBase64(trimmed);
  if (SUPPORTED_PREFIXES.some((prefix) => decoded.includes(prefix))) {
    return decoded;
  }
  return trimmed;
}

function parseLines(raw) {
  return raw
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

function buildNodeId(raw) {
  return crypto.createHash("sha1").update(raw).digest("hex");
}

function normalizeNetwork(raw) {
  const value = (raw || "tcp").toLowerCase();
  if (value === "websocket") {
    return "ws";
  }
  if (value === "h2") {
    return "http";
  }
  return value;
}

function normalizeSecurity(params) {
  const security = (params.get("security") || "").toLowerCase();
  if (security === "tls" || security === "reality") {
    return security;
  }
  const tls = (params.get("tls") || "").toLowerCase();
  if (tls && tls !== "0" && tls !== "false" && tls !== "none") {
    return "tls";
  }
  return "none";
}

function decodeMaybeBase64(input) {
  if (!input) {
    return "";
  }
  if (!/^[A-Za-z0-9+/=_-]+$/.test(input)) {
    return "";
  }
  return decodeBase64(input) || "";
}

function safeDecodeURIComponent(value) {
  if (!value) {
    return "";
  }
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function parseLegacyUserInfo(userInfo) {
  const parts = userInfo.split(":");
  if (parts.length >= 2) {
    return parts.slice(1).join(":");
  }
  return userInfo;
}

function parseShadowsocksUserInfo(userInfo) {
  if (!userInfo) {
    return null;
  }
  let value = userInfo;
  const decoded = decodeMaybeBase64(userInfo);
  if (decoded && decoded.includes(":")) {
    value = decoded;
  }
  value = safeDecodeURIComponent(value);
  const idx = value.indexOf(":");
  if (idx === -1) {
    return null;
  }
  const method = value.slice(0, idx).trim();
  const password = value.slice(idx + 1);
  if (!method || !password) {
    return null;
  }
  return { method, password };
}

function parseHostPort(value) {
  if (!value) {
    return null;
  }
  let host = "";
  let portRaw = "";
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    if (end === -1) {
      return null;
    }
    host = value.slice(1, end);
    if (value[end + 1] === ":") {
      portRaw = value.slice(end + 2);
    }
  } else {
    const idx = value.lastIndexOf(":");
    if (idx === -1) {
      return null;
    }
    host = value.slice(0, idx);
    portRaw = value.slice(idx + 1);
  }
  const port = Number.parseInt(portRaw, 10);
  if (!host || !port) {
    return null;
  }
  return {
    host: safeDecodeURIComponent(host),
    port
  };
}

function splitShadowsocksRaw(raw) {
  const hashIndex = raw.indexOf("#");
  const fragment = hashIndex >= 0 ? raw.slice(hashIndex + 1) : "";
  const withoutHash = hashIndex >= 0 ? raw.slice(0, hashIndex) : raw;
  const queryIndex = withoutHash.indexOf("?");
  const query = queryIndex >= 0 ? withoutHash.slice(queryIndex + 1) : "";
  const main = queryIndex >= 0 ? withoutHash.slice(0, queryIndex) : withoutHash;
  return { main, query, fragment };
}

function parseShadowsocksMain(main) {
  const trimmed = (main || "").trim();
  if (!trimmed) {
    return null;
  }
  const atIndex = trimmed.lastIndexOf("@");
  if (atIndex === -1) {
    const decoded = decodeMaybeBase64(trimmed);
    if (!decoded || decoded === trimmed) {
      return null;
    }
    return parseShadowsocksMain(decoded);
  }

  const userInfo = trimmed.slice(0, atIndex);
  const hostPart = trimmed.slice(atIndex + 1);
  const user = parseShadowsocksUserInfo(userInfo);
  const host = parseHostPort(hostPart);
  if (!user || !host) {
    return null;
  }
  return {
    address: host.host,
    port: host.port,
    method: user.method,
    password: user.password
  };
}

function parseVmessLegacy(decoded, params) {
  const clean = decoded.replace(/^vmess:\/\//, "");
  const atIndex = clean.indexOf("@");
  if (atIndex === -1) {
    return null;
  }
  const userPart = clean.slice(0, atIndex);
  const hostPart = clean.slice(atIndex + 1);
  const [address, portRaw] = hostPart.split(":");
  const port = Number.parseInt(portRaw, 10) || 443;
  const id = parseLegacyUserInfo(userPart);
  if (!id || !address || !port) {
    return null;
  }

  const name = params.get("remarks") || `${address}:${port}`;
  const user = {
    id,
    alterId: Number.parseInt(params.get("alterId") || params.get("aid") || 0, 10),
    security: "auto"
  };

  const streamSettings = buildStreamSettings({
    network: normalizeNetwork(params.get("obfs") || params.get("type") || params.get("network")),
    security: normalizeSecurity(params),
    path: params.get("path"),
    host: params.get("host") || params.get("obfsParam"),
    sni: params.get("sni") || params.get("peer"),
    alpn: params.get("alpn"),
    serviceName: params.get("serviceName") || params.get("service"),
    allowInsecure: params.get("allowInsecure")
  });

  return {
    name,
    protocol: "vmess",
    outbound: {
      protocol: "vmess",
      settings: {
        vnext: [
          {
            address,
            port,
            users: [user]
          }
        ]
      },
      streamSettings
    }
  };
}

function parseVmessJson(decoded) {
  let data;
  try {
    data = JSON.parse(decoded);
  } catch {
    return null;
  }

  const address = data.add || data.host;
  const port = Number.parseInt(data.port, 10);
  if (!address || !port) {
    return null;
  }
  const user = {
    id: data.id,
    alterId: Number.parseInt(data.aid || 0, 10),
    security: data.scy || "auto"
  };

  const streamSettings = buildStreamSettings({
    network: normalizeNetwork(data.net || "tcp"),
    security: data.tls === "tls" ? "tls" : "none",
    path: data.path,
    host: data.host,
    sni: data.sni,
    alpn: data.alpn,
    serviceName: data.serviceName
  });

  return {
    name: data.ps || `${address}:${port}`,
    protocol: "vmess",
    outbound: {
      protocol: "vmess",
      settings: {
        vnext: [
          {
            address,
            port,
            users: [user]
          }
        ]
      },
      streamSettings
    }
  };
}

function parseVmessUrl(line) {
  let url;
  try {
    url = new URL(line);
  } catch {
    return null;
  }
  const address = url.hostname;
  const port = Number.parseInt(url.port, 10) || 443;
  if (!address || !port) {
    return null;
  }
  const params = url.searchParams;
  let userInfo = url.username;
  const decodedUser = decodeMaybeBase64(userInfo);
  if (decodedUser) {
    userInfo = decodedUser;
  }
  const id = parseLegacyUserInfo(userInfo);
  if (!id) {
    return null;
  }

  const name = params.get("remarks") || decodeURIComponent(url.hash.replace(/^#/, "")) || `${address}:${port}`;
  const user = {
    id,
    alterId: Number.parseInt(params.get("alterId") || params.get("aid") || 0, 10),
    security: "auto"
  };

  const streamSettings = buildStreamSettings({
    network: normalizeNetwork(params.get("obfs") || params.get("type") || params.get("network")),
    security: normalizeSecurity(params),
    path: params.get("path"),
    host: params.get("host") || params.get("obfsParam"),
    sni: params.get("sni") || params.get("peer"),
    alpn: params.get("alpn"),
    serviceName: params.get("serviceName") || params.get("service"),
    allowInsecure: params.get("allowInsecure")
  });

  return {
    name,
    protocol: "vmess",
    outbound: {
      protocol: "vmess",
      settings: {
        vnext: [
          {
            address,
            port,
            users: [user]
          }
        ]
      },
      streamSettings
    }
  };
}

function parseVmess(line) {
  const raw = line.slice("vmess://".length);
  const [payload, queryString] = raw.split("?");
  const params = new URLSearchParams(queryString || "");
  const decodedPayload = decodeBase64(payload);
  if (decodedPayload) {
    const trimmed = decodedPayload.trim();
    const jsonParsed = parseVmessJson(trimmed);
    if (jsonParsed) {
      return jsonParsed;
    }
    const legacyParsed = parseVmessLegacy(trimmed, params);
    if (legacyParsed) {
      return legacyParsed;
    }
  }
  return parseVmessUrl(line);
}

function parseShadowsocks(line) {
  const raw = line.slice("ss://".length);
  let name = "";
  let address = "";
  let port = 0;
  let method = "";
  let password = "";
  let url = null;

  try {
    url = new URL(line);
  } catch {
    url = null;
  }

  if (url) {
    name = safeDecodeURIComponent(url.hash.replace(/^#/, ""));
    if (url.hostname && url.port) {
      address = url.hostname;
      port = Number.parseInt(url.port, 10) || 0;
      if (url.username && url.password) {
        method = url.username;
        password = url.password;
      } else if (url.username) {
        const info = parseShadowsocksUserInfo(url.username);
        if (info) {
          method = info.method;
          password = info.password;
        }
      }
    }
  }

  if (!address || !port || !method || !password) {
    const { main, fragment } = splitShadowsocksRaw(raw);
    if (!name) {
      name = safeDecodeURIComponent(fragment);
    }
    const parsed = parseShadowsocksMain(main);
    if (parsed) {
      address = parsed.address;
      port = parsed.port;
      method = parsed.method;
      password = parsed.password;
    }
  }

  if (!address || !port || !method || !password) {
    return null;
  }

  const displayName = name || `${address}:${port}`;
  return {
    name: displayName,
    protocol: "shadowsocks",
    outbound: {
      protocol: "shadowsocks",
      settings: {
        servers: [
          {
            address,
            port,
            method,
            password
          }
        ]
      }
    }
  };
}

function parseUrlBased(line, protocol) {
  let url;
  try {
    url = new URL(line);
  } catch {
    return null;
  }
  const address = url.hostname;
  const port = Number.parseInt(url.port, 10) || 443;
  if (!address || !port) {
    return null;
  }
  const params = url.searchParams;
  const name = decodeURIComponent(url.hash.replace(/^#/, "")) || `${address}:${port}`;

  const streamSettings = buildStreamSettings({
    network: params.get("type") || params.get("network") || "tcp",
    security: params.get("security") || "none",
    path: params.get("path"),
    host: params.get("host"),
    sni: params.get("sni") || params.get("peer"),
    alpn: params.get("alpn"),
    serviceName: params.get("serviceName") || params.get("service"),
    reality: {
      publicKey: params.get("pbk"),
      shortId: params.get("sid"),
      spiderX: params.get("spx")
    },
    allowInsecure: params.get("allowInsecure")
  });

  if (protocol === "vless") {
    const id = url.username;
    if (!id) {
      return null;
    }
    const flow = params.get("flow") || undefined;
    return {
      name,
      protocol,
      outbound: {
        protocol: "vless",
        settings: {
          vnext: [
            {
              address,
              port,
              users: [
                {
                  id,
                  encryption: "none",
                  flow
                }
              ]
            }
          ]
        },
        streamSettings
      }
    };
  }

  if (protocol === "trojan") {
    const password = url.username;
    if (!password) {
      return null;
    }
    return {
      name,
      protocol,
      outbound: {
        protocol: "trojan",
        settings: {
          servers: [
            {
              address,
              port,
              password
            }
          ]
        },
        streamSettings
      }
    };
  }

  return null;
}

function buildStreamSettings({
  network,
  security,
  path,
  host,
  sni,
  alpn,
  serviceName,
  reality,
  allowInsecure
}) {
  const settings = {
    network,
    security: security === "tls" || security === "reality" ? security : "none"
  };

  if (settings.security === "tls") {
    settings.tlsSettings = {
      serverName: sni || host || undefined,
      alpn: alpn ? alpn.split(",").map((item) => item.trim()).filter(Boolean) : undefined,
      allowInsecure: allowInsecure === "1" || allowInsecure === "true"
    };
  }

  if (settings.security === "reality") {
    settings.realitySettings = {
      serverName: sni || host || undefined,
      publicKey: reality?.publicKey || undefined,
      shortId: reality?.shortId || undefined,
      spiderX: reality?.spiderX || undefined
    };
  }

  if (network === "ws") {
    settings.wsSettings = {
      path: path || "/",
      headers: host ? { Host: host } : undefined
    };
  }

  if (network === "grpc") {
    settings.grpcSettings = {
      serviceName: serviceName || ""
    };
  }

  return settings;
}

export function parseSubscription(raw, sourceId, sourceName) {
  const content = maybeDecodeSubscription(raw);
  let lines = parseLines(content);
  if (lines.length === 1 && !startsWithSupportedPrefix(lines[0])) {
    const decoded = decodeBase64(lines[0]);
    if (decoded && SUPPORTED_PREFIXES.some((prefix) => decoded.includes(prefix))) {
      lines = parseLines(decoded);
    }
  }
  const nodes = [];

  for (const rawLine of lines) {
    const line = maybeDecodeLine(rawLine.trim());
    let parsed = null;
    if (line.startsWith("vmess://")) {
      parsed = parseVmess(line);
    } else if (line.startsWith("vless://")) {
      parsed = parseUrlBased(line, "vless");
    } else if (line.startsWith("trojan://")) {
      parsed = parseUrlBased(line, "trojan");
    } else if (line.startsWith("ss://")) {
      parsed = parseShadowsocks(line);
    }

    if (!parsed) {
      continue;
    }

    const id = buildNodeId(line);
    nodes.push({
      id,
      name: parsed.name,
      protocol: parsed.protocol,
      outbound: parsed.outbound,
      raw: line,
      sourceId,
      sourceName
    });
  }

  return nodes;
}

export function summarizeNode(node) {
  return {
    id: node.id,
    name: node.name,
    protocol: node.protocol,
    sourceId: node.sourceId,
    sourceName: node.sourceName
  };
}
