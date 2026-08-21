#!/usr/bin/env bash
# Brings the compose stack up from nothing and waits for control to report
# ready. Everything before that — schema, CA chain, every service certificate —
# has to have worked for this to pass.
set -euo pipefail

cd "$(dirname "$0")/../.."

[ -f .env ] || cp .env.example .env
./deploy/compose/gen-infra-certs.sh

docker compose up -d --build postgres redis bootstrap ca control

for _ in $(seq 1 90); do
  if curl -fsS http://localhost:8080/ready >/dev/null 2>&1; then
    echo "control ready"
    exit 0
  fi
  sleep 2
done

docker compose logs control ca bootstrap
echo "control did not become ready" >&2
exit 1
