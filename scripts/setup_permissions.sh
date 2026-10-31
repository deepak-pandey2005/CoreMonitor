#!/usr/bin/env bash
# Helper script to configure packet sniffing permissions on Linux for uv and virtualenv

set -e

echo "=== CoreMonitor Network Permissions Setup (uv) ==="
echo ""

# Ensure uv virtual environment exists
if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment with uv..."
    uv sync
fi

VENV_PYTHON="$(pwd)/.venv/bin/python"

if [ -f "$VENV_PYTHON" ]; then
    echo "[*] Setting CAP_NET_RAW and CAP_NET_ADMIN on: $VENV_PYTHON"
    sudo setcap cap_net_raw,cap_net_admin=eip "$VENV_PYTHON"
    echo ""
    echo "[+] Done! You can now run CoreMonitor live without sudo using uv:"
    echo "    uv run coremonitor live -i wlan0"
else
    echo "[-] Virtual environment python binary not found at $VENV_PYTHON"
    exit 1
fi
