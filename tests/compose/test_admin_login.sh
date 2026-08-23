#!/usr/bin/env bash
# The admin API must come up, authenticate the bootstrap owner, reach control
# over mTLS, and issue an enrollment token.
set -euo pipefail
cd "$(dirname "$0")/../.."
BASE=${BASE:-http://localhost:8080}

docker compose up -d --wait postgres redis bootstrap ca control admin

for i in $(seq 1 60); do
  if curl -fsS "$BASE/ready" >/dev/null 2>&1; then break; fi
  sleep 2
done
curl -fsS "$BASE/ready" | grep -q '"ready":true' || { docker compose logs admin; echo "admin never became ready" >&2; exit 1; }

EMAIL=$(grep '^ADMIN_EMAIL=' .env | cut -d= -f2)
PASSWORD=$(grep '^ADMIN_PASSWORD=' .env | cut -d= -f2)
TOKEN=$(curl -fsS -X POST "$BASE/api/v1/users/login" -H 'content-type: application/json' \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | jq -r '.access_token // empty')
[ -n "$TOKEN" ] || { echo "login did not return an access token" >&2; exit 1; }

curl -fsS "$BASE/api/v1/devices" -H "Authorization: Bearer $TOKEN" | jq -e '.items' >/dev/null

ENROLL=$(curl -fsS -X POST "$BASE/api/v1/devices/enroll-tokens" -H "Authorization: Bearer $TOKEN" \
  -H 'content-type: application/json' -d '{"device_name":"smoke","max_uses":1,"expires_in_hours":1}' | jq -r '.token')
[ -n "$ENROLL" ] && [ "$ENROLL" != "null" ] || { echo "no enrollment token issued" >&2; exit 1; }

# The admin API must be talking to control, not guessing.
curl -fsS -X POST "$BASE/api/v1/policies/explain" -H "Authorization: Bearer $TOKEN" -H 'content-type: application/json' \
  -d '{"device_id":"00000000-0000-0000-0000-000000000000","destination":"10.20.0.1","protocol":"tcp","port":443}' \
  | jq -e 'has("allow")' >/dev/null

# Docs stay off outside development.
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/docs")
[ "$code" = "404" ] || { echo "/docs should be disabled (got $code)" >&2; exit 1; }

echo "admin login and control wiring ok"
