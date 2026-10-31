#!/usr/bin/env bash
# Helper script to configure packet sniffing permissions on Linux without requiring full root access

set -e

echo "=== CoreMonitor Network Permissions Setup ==="
echo ""
echo "Choose an option to grant packet sniffing capabilities:"
echo "1) Grant CAP_NET_RAW and CAP_NET_ADMIN to Python virtual environment"
echo "2) Add current user to 'wireshark' group"
echo ""

VENV_PYTHON="$(pwd)/.venv/bin/python"

if [ -f "$VENV_PYTHON" ]; then
    echo "[*] Setting capabilities on: $VENV_PYTHON"
    sudo setcap cap_net_raw,cap_net_admin=eip "$VENV_PYTHON"
    echo "[+] Done! You can now run CoreMonitor live without sudo: .venv/bin/python -m coremonitor live"
else
    echo "[-] Virtual environment not found at .venv. Please create it first: python3 -m venv .venv"
fi
