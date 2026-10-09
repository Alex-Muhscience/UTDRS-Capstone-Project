#!/usr/bin/env bash
# Start the core engine and the API gateway against a MongoDB, then run tests/system.
#
#   MONGODB_URI   MongoDB to use (default mongodb://localhost:27017); a throwaway
#                 database is created and dropped.
#   GATEWAY_PYTHON / ENGINE_PYTHON
#                 Python interpreters with each service's requirements installed
#                 (default: python3 for both).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
MONGODB_URI="${MONGODB_URI:-mongodb://localhost:27017}"
GATEWAY_PYTHON="${GATEWAY_PYTHON:-python3}"
ENGINE_PYTHON="${ENGINE_PYTHON:-python3}"
DB_NAME="utdrs_system_$(date +%s)"
TOKEN="system-test-$(date +%s)"
LOGS="$(mktemp -d)"

cleanup() {
  kill "${ENGINE_PID:-}" "${GATEWAY_PID:-}" 2>/dev/null || true
  "$GATEWAY_PYTHON" - "$MONGODB_URI" "$DB_NAME" <<'PY' || true
import sys
from pymongo import MongoClient
with MongoClient(sys.argv[1]) as client:
    client.drop_database(sys.argv[2])
PY
}
trap cleanup EXIT

wait_for() {
  for _ in $(seq 1 60); do
    if curl -fsS "$1" >/dev/null 2>&1; then return 0; fi
    sleep 1
  done
  echo "Timed out waiting for $1" >&2
  cat "$LOGS"/*.log >&2
  return 1
}

(cd "$ROOT/services/core-engine" && \
  MONGODB_URI="$MONGODB_URI" DB_NAME="$DB_NAME" INTERNAL_API_TOKEN="$TOKEN" ENABLE_THREAT_INTEL=false \
  "$ENGINE_PYTHON" -m uvicorn app:app --port 8001 >"$LOGS/engine.log" 2>&1) &
ENGINE_PID=$!

(cd "$ROOT/services/api-gateway" && \
  MONGODB_URI="$MONGODB_URI" DB_NAME="$DB_NAME" JWT_SECRET="$TOKEN-jwt" \
  CORE_ENGINE_URL=http://localhost:8001 INTERNAL_API_TOKEN="$TOKEN" \
  "$GATEWAY_PYTHON" -m uvicorn app:app --port 8000 >"$LOGS/gateway.log" 2>&1) &
GATEWAY_PID=$!

wait_for http://localhost:8001/health
wait_for http://localhost:8000/api/v1/health

GATEWAY_URL=http://localhost:8000 "$GATEWAY_PYTHON" -m pytest -q -p no:cacheprovider "$ROOT/tests/system"
