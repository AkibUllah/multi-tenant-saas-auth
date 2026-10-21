#!/usr/bin/env bash
# Codespaces start hook: bring up API + PostgreSQL + Redis and seed a demo user with an organization.
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose up -d --build

echo "waiting for the API on :8000 ..."
for _ in $(seq 1 60); do
  if curl -fsS http://127.0.0.1:8000/health >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

BASE=http://127.0.0.1:8000
EMAIL=rahim@example.com
PASSWORD=correct-horse-battery
if [ ! -f .demo-seeded ]; then
  curl -fsS -X POST "$BASE/v1/auth/register" -H 'content-type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\",\"full_name\":\"Rahim Uddin\"}" >/dev/null
  ACCESS=$(curl -fsS -X POST "$BASE/v1/auth/login" -H 'content-type: application/json' \
    -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["access_token"])')
  ORG=$(curl -fsS -X POST "$BASE/v1/orgs" -H "authorization: Bearer $ACCESS" \
    -H 'content-type: application/json' -d '{"name":"Dhaka Fintech Ltd"}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
  curl -fsS -X POST "$BASE/v1/orgs/$ORG/projects" -H "authorization: Bearer $ACCESS" \
    -H 'content-type: application/json' -d '{"name":"bKash integration"}' >/dev/null
  date -u +%FT%TZ > .demo-seeded
fi

cat <<MSG

Multi-tenant SaaS Auth is up.
  API docs:      forwarded port 8000, path /docs
  Demo account:  $EMAIL / $PASSWORD  (owner of "Dhaka Fintech Ltd", one project)
  Log in via POST /v1/auth/login, then "Authorize" in Swagger with the access token.
MSG
