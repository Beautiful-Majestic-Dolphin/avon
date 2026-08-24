#!/usr/bin/env bash
# Brings the compose stack up from nothing and waits for control to report
# ready. Everything before that — schema, CA chain, every service certificate —
# has to have worked for this to pass.
set -euo pipefail

cd "$(dirname "$0")/../.."

[ -f .env ] || cp .env.example .env
./deploy/compose/gen-infra-certs.sh

docker compose up -d --build postgres redis bootstrap ca control

# Ask compose for control's actual published host port rather than assuming
# it — 8080 collides with admin, so control publishes on 8090 (see
# docker-compose.yml), and that mapping is compose's to decide, not ours to
# hardcode a second time.
control_port="$(docker compose port control 8080 | cut -d: -f2)"

for _ in $(seq 1 90); do
  if curl -fsS "http://localhost:${control_port}/ready" >/dev/null 2>&1; then
    echo "control ready"
    exit 0
  fi
  sleep 2
done

docker compose logs control ca bootstrap
echo "control did not become ready" >&2
exit 1
