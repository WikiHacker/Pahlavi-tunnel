#!/usr/bin/env bash
set -e

REPO="https://raw.githubusercontent.com/Zehnovik/ilyaahmadi-tunnel/main"

MANAGER_URL="$REPO/IlyaAhmadi-Tunnel.sh"
PY_URL="$REPO/ilyaahmadi.py"

BIN="/usr/local/bin/pahlavi-tunnel"
PY_DST="/usr/local/bin/ilyaahmadi.py"

echo "[*] Installing dependencies..."
apt update -y >/dev/null 2>&1 || true
apt install -y curl screen python3 >/dev/null 2>&1

echo "[*] Downloading manager..."
curl -fsSL "$MANAGER_URL" -o "$BIN"

echo "[*] Downloading tunnel core..."
curl -fsSL "$PY_URL" -o "$PY_DST"

chmod +x "$BIN"
chmod +x "$PY_DST"

echo ""
echo "[+] Installation completed!"
echo ""
echo "Manager installed at: $BIN"
echo "Tunnel core installed at: $PY_DST"
echo ""
echo "Run it with:"
echo "sudo pahlavi-tunnel"
