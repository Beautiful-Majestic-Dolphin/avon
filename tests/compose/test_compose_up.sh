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
#
# `docker compose port` can emit "0.0.0.0:8090", "127.0.0.1:8090",
# "[::1]:8090", "[::]:8090", or — on an IPv6-enabled daemon — two lines (an
# IPv4 mapping and an IPv6 one). `head -n1` takes the first mapping; `sed`
# strips everything up to and including the rightmost ':', which is the
# port separator in every one of those shapes (IPv6 addresses embed ':' but
# never after the closing ']').
control_port="$(docker compose port control 8080 | head -n1 | sed 's/.*://')"

case "$control_port" in
  ''|*[!0-9]*)
    echo "could not resolve control's published port from 'docker compose port control 8080'" >&2
    exit 1
    ;;
esac

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
