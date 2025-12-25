#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_NAME="s5route"
SERVICE_PATH="/etc/systemd/system/${SERVICE_NAME}.service"

SUDO_CMD="sudo"
if [[ "${EUID}" -eq 0 ]]; then
  SUDO_CMD=""
elif ! command -v sudo >/dev/null 2>&1; then
  echo "sudo not found. Please run this script as root." >&2
  exit 1
fi

min_node_major=18

get_node_major() {
  node -p "process.versions.node.split('.')[0]" 2>/dev/null || echo ""
}

install_node() {
  echo "Installing Node.js 20.x via NodeSource..."
  ${SUDO_CMD} apt-get update -y
  ${SUDO_CMD} apt-get install -y ca-certificates curl gnupg
  curl -fsSL https://deb.nodesource.com/setup_20.x | ${SUDO_CMD} -E bash -
  ${SUDO_CMD} apt-get install -y nodejs
}

NODE_BIN="$(command -v node || true)"
if [[ -z "$NODE_BIN" ]]; then
  install_node
  NODE_BIN="$(command -v node || true)"
fi

NODE_MAJOR="$(get_node_major)"
if [[ -z "$NODE_MAJOR" || "$NODE_MAJOR" -lt "$min_node_major" ]]; then
  install_node
  NODE_MAJOR="$(get_node_major)"
fi

if [[ -z "$NODE_MAJOR" || "$NODE_MAJOR" -lt "$min_node_major" ]]; then
  echo "Node.js version must be >= ${min_node_major}. Please upgrade and retry." >&2
  exit 1
fi

NPM_BIN="$(command -v npm || true)"
if [[ -z "$NPM_BIN" ]]; then
  echo "npm not found in PATH. Please install Node.js 18+ (npm included) and retry." >&2
  exit 1
fi

APP_USER="${SUDO_USER:-$(whoami)}"

mkdir -p "${ROOT_DIR}/data"

echo "Installing npm dependencies..."
if [[ -f "${ROOT_DIR}/package-lock.json" ]]; then
  (cd "${ROOT_DIR}" && "${NPM_BIN}" ci --omit=dev)
else
  (cd "${ROOT_DIR}" && "${NPM_BIN}" install --omit=dev)
fi

cat <<SERVICE | sudo tee "$SERVICE_PATH" >/dev/null
[Unit]
Description=s5route (V2Ray outbound selector)
After=network.target

[Service]
Type=simple
WorkingDirectory=${ROOT_DIR}
ExecStart=${NODE_BIN} ${ROOT_DIR}/server.js
Restart=on-failure
RestartSec=2
User=${APP_USER}
Environment=NODE_ENV=production
Environment=PORT=22007
EnvironmentFile=-/etc/default/s5route

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable --now "$SERVICE_NAME"

echo "Installed and started: ${SERVICE_NAME}"
echo "Service file: ${SERVICE_PATH}"
