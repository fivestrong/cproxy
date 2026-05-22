#!/bin/bash
# E2E coverage for the new `--upstream` mode (HTTP CONNECT and SOCKS5 against
# a local xray instance that exposes both an HTTP and a SOCKS5 inbound).
#
# Layout:
#   * cproxy --upstream http://127.0.0.1:1083  -> xray http inbound 1083
#   * cproxy --upstream socks5://127.0.0.1:1084 -> xray socks inbound 1084
#
# We rely on `cproxy --port 1090` being a local listener that the bridge owns
# itself. Each redirect rule sends the cgroup's TCP traffic to 1090 and the
# bridge re-opens the connection via the chosen upstream proxy.

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
    },
    {
      "port": 1084,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": false
      }
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

run_cproxy_upstream() {
    local label=$1
    local upstream=$2
    echo "=== cproxy upstream: $label ($upstream) ==="
    sudo env RUST_LOG=debug cproxy \
        --port 1090 \
        --upstream "$upstream" \
        -- curl -s -I --max-time 15 https://www.google.com > /dev/null
}

main() {
    install_xray_if_missing
    write_xray_config
    start_xray

    run_cproxy_upstream "HTTP CONNECT" "http://127.0.0.1:1083"
    run_cproxy_upstream "SOCKS5 no-auth" "socks5://127.0.0.1:1084"

    echo "--upstream e2e tests passed."
}

main
