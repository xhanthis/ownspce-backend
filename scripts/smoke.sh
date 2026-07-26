#!/usr/bin/env bash
# Smoke test the unauthenticated surface of a deployed Ownspce API.
# Usage: scripts/smoke.sh [base_url]   (default https://api.ownspce.com/v1)
set -euo pipefail

BASE="${1:-https://api.ownspce.com/v1}"
fails=0

check() {
  local label="$1" want="$2" got="$3"
  if [[ "$got" == "$want" ]]; then
    printf '  ok   %-34s %s\n' "$label" "$got"
  else
    printf '  FAIL %-34s got %s, want %s\n' "$label" "$got" "$want"
    fails=$((fails + 1))
  fi
}

status() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "smoke: $BASE"

check "GET /health" 200 "$(status "$BASE/health")"
check "GET /.well-known/jwks.json" 200 "$(status "$BASE/.well-known/jwks.json")"
check "GET /me unauthenticated" 401 "$(status "$BASE/me")"
check "GET /spaces unauthenticated" 401 "$(status "$BASE/spaces")"
check "GET unknown route" 404 "$(status "$BASE/nope")"
check "GET /users/nosuchuser_zz" 404 "$(status "$BASE/users/nosuchuser_zz")"
check "POST /auth/session bad provider" 400 \
  "$(status -X POST "$BASE/auth/session" -H 'content-type: application/json' \
     -d '{"provider":"nope","idToken":"x","device":{"label":"l","platform":"macos","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}')"
check "POST /auth/session bad key size" 400 \
  "$(status -X POST "$BASE/auth/session" -H 'content-type: application/json' \
     -d '{"provider":"google","idToken":"x","device":{"label":"l","platform":"macos","publicKey":"AAAA"}}')"
check "GET /public/pages missing page" 404 "$(status "$BASE/public/pages/nosuchuser_zz/nosuchpage")"

echo
echo "health: $(curl -s "$BASE/health")"

if (( fails > 0 )); then
  echo "FAILED: $fails check(s)"
  exit 1
fi
echo "all checks passed"
