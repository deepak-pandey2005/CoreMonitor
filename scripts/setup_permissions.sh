#!/usr/bin/env bash
# Helper script to configure packet sniffing permissions for CoreMonitor binary on Linux

set -e

echo "=== CoreMonitor Network Permissions Setup ==="
echo ""

BINARY="$(pwd)/bin/coremonitor"

if [ -f "$BINARY" ]; then
    echo "[*] Granting CAP_NET_RAW and CAP_NET_ADMIN capabilities to: $BINARY"
    sudo setcap cap_net_raw,cap_net_admin=eip "$BINARY"
    echo "[+] Done! You can now run CoreMonitor live without sudo: ./bin/coremonitor live -i wlan0"
else
    echo "[-] Binary not found at $BINARY. Build it first with: make"
    exit 1
fi
