#!/usr/bin/env bash
# Run the core engine and the API gateway against a MongoDB, connected to each other.
#
#   scripts/run-stack.sh                    start both and wait; Ctrl-C stops them
#   scripts/run-stack.sh <command> [args]   start both, run the command, then stop them
#                                           (exits with the command's status)
#
# Environment:
#   MONGODB_URI      MongoDB to use (default mongodb://localhost:27017)
#   DB_NAME          the gateway's database; when unset, throwaway databases are created
#                    and dropped on exit
#   ENGINE_DB_NAME   the core engine's database (default: DB_NAME with an _engine suffix).
#                    The two services must not share a database.
#   GATEWAY_PYTHON / ENGINE_PYTHON
#                    Python interpreters with each service's requirements installed
#                    (default: python3 for both)
#   GATEWAY_PORT / ENGINE_PORT  (default 8000 / 8001)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export MONGODB_URI="${MONGODB_URI:-mongodb://localhost:27017}"
GATEWAY_PYTHON="${GATEWAY_PYTHON:-python3}"
ENGINE_PYTHON="${ENGINE_PYTHON:-python3}"
GATEWAY_PORT="${GATEWAY_PORT:-8000}"
ENGINE_PORT="${ENGINE_PORT:-8001}"
if [ -z "${DB_NAME:-}" ]; then
  DB_NAME="utdrs_stack_$(date +%s)"
  DROP_DB=1
fi
ENGINE_DB_NAME="${ENGINE_DB_NAME:-${DB_NAME}_engine}"
# A fresh secret per run: tokens from an earlier run stop working, as they should.
TOKEN="stack-$(date +%s)-$RANDOM"
LOGS="$(mktemp -d)"

cleanup() {
  kill "${ENGINE_PID:-}" "${GATEWAY_PID:-}" 2>/dev/null || true
  wait 2>/dev/null || true
  if [ -n "${DROP_DB:-}" ] && [ -n "${STARTED:-}" ]; then
    "$GATEWAY_PYTHON" - "$MONGODB_URI" "$DB_NAME" "$ENGINE_DB_NAME" <<'PY' || true
import sys
from pymongo import MongoClient
with MongoClient(sys.argv[1]) as client:
    for name in sys.argv[2:]:
        client.drop_database(name)
PY
  fi
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

for port in "$ENGINE_PORT" "$GATEWAY_PORT"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "Port $port is already in use; stop whatever is listening there first." >&2
    exit 1
  fi
done

STARTED=1
(cd "$ROOT/services/core-engine" && \
  DB_NAME="$ENGINE_DB_NAME" INTERNAL_API_TOKEN="$TOKEN" ENABLE_THREAT_INTEL=false \
  exec "$ENGINE_PYTHON" -m uvicorn app:app --port "$ENGINE_PORT" >"$LOGS/engine.log" 2>&1) &
ENGINE_PID=$!

(cd "$ROOT/services/api-gateway" && \
  DB_NAME="$DB_NAME" JWT_SECRET="$TOKEN-jwt" \
  CORE_ENGINE_URL="http://localhost:$ENGINE_PORT" INTERNAL_API_TOKEN="$TOKEN" \
  exec "$GATEWAY_PYTHON" -m uvicorn app:app --port "$GATEWAY_PORT" >"$LOGS/gateway.log" 2>&1) &
GATEWAY_PID=$!

wait_for "http://localhost:$ENGINE_PORT/health"
wait_for "http://localhost:$GATEWAY_PORT/api/v1/health"
echo "Core engine on :$ENGINE_PORT (database $ENGINE_DB_NAME), API gateway on :$GATEWAY_PORT (database $DB_NAME); logs in $LOGS"

if [ $# -eq 0 ]; then
  wait
else
  set +e
  "$@"
  status=$?
  set -e
  if [ $status -ne 0 ]; then
    echo "--- gateway log" >&2; tail -n 50 "$LOGS/gateway.log" >&2
    echo "--- engine log" >&2; tail -n 50 "$LOGS/engine.log" >&2
  fi
  exit $status
fi
