#!/usr/bin/env bash
# Start the core engine and the API gateway (scripts/run-stack.sh), then run tests/system
# against them. Takes the same environment variables as run-stack.sh.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
exec "$ROOT/scripts/run-stack.sh" \
  env GATEWAY_URL="http://localhost:${GATEWAY_PORT:-8000}" \
  "${GATEWAY_PYTHON:-python3}" -m pytest -q -p no:cacheprovider "$ROOT/tests/system"
