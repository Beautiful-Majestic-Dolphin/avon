#!/usr/bin/env bash
set -euo pipefail
# Smoke test for the data-plane: agents connect and reach the protected target
# through the gateway. Requires a working docker compose stack with NET_ADMIN.

COMPOSE="docker compose -f docker-compose.yml -f tests/e2e/docker-compose.e2e.yml"

echo "=> building and starting stack"
$COMPOSE up -d --build

echo "=> waiting for agent-a to connect (up to 120s)"
for i in $(seq 1 60); do
  if $COMPOSE exec -T agent-a avon-agent status --json 2>/dev/null | grep -q '"state":"connected"'; then
    echo "agent-a connected"
    break
  fi
  sleep 2
  if [ "$i" -eq 60 ]; then
    echo "agent-a never reached connected"
    $COMPOSE exec -T agent-a avon-agent status --json || true
    $COMPOSE logs agent-a || true
    exit 1
  fi
done

echo "=> checking agent-a status"
$COMPOSE exec -T agent-a avon-agent status --json | tee /tmp/agent-a.json | grep -q '"state":"connected"'

echo "=> curl target through tunnel"
$COMPOSE exec -T agent-a curl -fsS --max-time 5 http://172.30.0.10/ | grep -qi "nginx"

echo "tunnel up: agent-a reached target through the gateway"
