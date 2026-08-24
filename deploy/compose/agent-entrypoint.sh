#!/bin/sh
set -eu
if [ ! -f /var/lib/avon/identity.json ]; then
  if [ -f /certs/enroll.token ]; then
    TOKEN_FILE="/certs/enroll.token"
  elif [ -n "${AVON_AGENT_ENROLL_TOKEN:-}" ]; then
    TOKEN_FILE=""
  else
    echo "no enroll token: /certs/enroll.token or AVON_AGENT_ENROLL_TOKEN required" >&2
    exit 1
  fi
  if [ -n "${TOKEN_FILE:-}" ]; then
    avon-agent enroll --control "https://control:50051" --token-file "$TOKEN_FILE" --ca-file /certs/trust-ca.crt --data-dir /var/lib/avon --key-provider "${AVON_AGENT_KEY_PROVIDER:-auto}"
  else
    avon-agent enroll --control "https://control:50051" --token "$AVON_AGENT_ENROLL_TOKEN" --ca-file /certs/trust-ca.crt --data-dir /var/lib/avon --key-provider "${AVON_AGENT_KEY_PROVIDER:-auto}"
  fi
fi
mkdir -p /etc/avon
cat > /etc/avon/agent.toml <<EOF
control_plane = "control:50051"
data_dir = "/var/lib/avon"
pulse_interval_secs = ${AVON_AGENT_PULSE_INTERVAL_SECS:-10}
tun_name = "${AVON_AGENT_TUN_NAME:-avon0}"
overlay_mtu = 1280
fail_open = ${AVON_AGENT_FAIL_OPEN:-false}
EOF
# The container is root and has no privileged helper beside it, so the agent
# creates the TUN itself. Installed systems run the other way round.
exec avon-agent run --config /etc/avon/agent.toml --no-helper
