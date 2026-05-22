#!/bin/bash
# E2E coverage for `--firewall nft`. Reuses the same xray HTTP inbound the
# upstream tests bring up so we exercise the bridge + nft redirect rules in
# combination.
#
# Skips automatically when:
#   * /sys/fs/cgroup/cgroup.controllers is missing (host is on cgroup v1), or
#   * the running kernel does not support `nft socket cgroupv2`.

set -euo pipefail

XRAY_PID=""

cleanup() {
    if [ -n "${XRAY_PID:-}" ] && ps -p "$XRAY_PID" > /dev/null 2>&1; then
        echo "Stopping xray (PID $XRAY_PID)"
        sudo kill "$XRAY_PID" || true
        wait "$XRAY_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

if ! command -v nft >/dev/null 2>&1; then
    echo "nft not installed; skipping nft backend tests."
    exit 0
fi

if [ ! -f /sys/fs/cgroup/cgroup.controllers ]; then
    echo "host is on cgroup v1; nft backend not supported, skipping."
    exit 0
fi

# Probe whether the kernel/nftables combination on this host actually
# understands `socket cgroupv2`. We do this by trying to create a throwaway
# table; if the parser rejects it, fall back gracefully.
PROBE_OUT=$(sudo nft -c -- "add table ip cproxy_probe; add chain ip cproxy_probe c { type filter hook output priority 0; }; add rule ip cproxy_probe c socket cgroupv2 level 1 \"x\" return" 2>&1 || true)
if echo "$PROBE_OUT" | grep -qi "syntax error\|unknown\|invalid"; then
    echo "nft on this host does not support 'socket cgroupv2': $PROBE_OUT"
    echo "skipping."
    exit 0
fi

install_xray_if_missing() {
    if command -v xray >/dev/null 2>&1; then
        return
    fi
    echo "Installing xray..."
    bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install
}

write_xray_config() {
    cat > /tmp/xray_upstream.json <<'EOF'
{
  "inbounds": [
    {
      "port": 1083,
      "listen": "127.0.0.1",
      "protocol": "http",
      "settings": {}
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    }
  ]
}
EOF
}

start_xray() {
    sudo xray -config /tmp/xray_upstream.json &
    XRAY_PID=$!
    sleep 2
    echo "xray started (PID $XRAY_PID)"
}

main() {
    install_xray_if_missing
    write_xray_config
    start_xray

    echo "=== cproxy --firewall nft + --upstream http ==="
    sudo env RUST_LOG=debug cproxy \
        --firewall nft \
        --port 1090 \
        --upstream http://127.0.0.1:1083 \
        -- curl -s -I --max-time 15 https://www.google.com > /dev/null

    echo "nft backend e2e test passed."
}

main
