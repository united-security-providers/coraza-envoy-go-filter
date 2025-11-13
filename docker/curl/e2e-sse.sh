#!/usr/bin/env bash
# e2e/e2e-sse.sh — E2E test for SSE endpoint (via Envoy), with readiness on SSE health
#
# This script is intended to run inside the tests container defined in e2e/docker-compose.yml.
# It first waits for the SSE server health endpoint to be ready, then connects to Envoy and
# verifies that the SSE endpoint streams at least two messages containing the text "Server time:".
#
# Environment variables shared across e2e scripts:
#   ENVOY_HOST       host:port of Envoy (default: envoy:8081)
#   HTTPBIN_HOST     host:port of httpbin (unused here, but accepted for symmetry)
#   SSE_HOST         host:port of SSE server (default: sse-server:8080)
#   SSE_PATH         SSE events path (default: /events)
#   HEALTH_PATH      SSE health path (default: /healthz)
#   CONNECT_TIMEOUT  curl connect-timeout seconds (default: 5)
#   MAX_TIME         curl max total time seconds for SSE fetch (default: 15)
#
set -eu

ENVOY_HOST=${ENVOY_HOST:-envoy:8081}
HTTPBIN_HOST=${HTTPBIN_HOST:-httpbin:8080}
SSE_HOST=${SSE_HOST:-sse-server:8080}
SSE_PATH=${SSE_PATH:-/events}
HEALTH_PATH=${HEALTH_PATH:-/healthz}
CONNECT_TIMEOUT=${CONNECT_TIMEOUT:-5}
MAX_TIME=${MAX_TIME:-15}

HEALTH_URL="http://${SSE_HOST}${HEALTH_PATH}"
TARGET_URL="http://${ENVOY_HOST}${SSE_PATH}"

# Wait for SSE server health readiness
echo "[INFO] Waiting for SSE server health at ${HEALTH_URL}..."
for i in {1..40}; do
  # Expect HTTP 200 and body 'ok' (lenient: just HTTP 200 is sufficient)
  if status=$(curl -sS --connect-timeout 1 --max-time 1 -w "%{http_code}" -o /dev/null "${HEALTH_URL}"); then
    if [ "$status" = "200" ]; then
      echo "[INFO] SSE server is healthy (status ${status})."
      break
    fi
  fi
  sleep 0.5
  if [ "$i" -eq 40 ]; then
    echo "[ERROR] SSE server health endpoint not ready at ${HEALTH_URL}"
    exit 1
  fi
done

# Now fetch SSE stream via Envoy without a WAF
echo "[INFO] Connecting to SSE stream ${TARGET_URL} (without coraza) and capturing at least 4 events..."
#curl -H "Host: no-waf.example.com"  -sS --no-buffer  --connect-timeout "${CONNECT_TIMEOUT}" --max-time "${MAX_TIME}" "${TARGET_URL}" -v

DATA_OUT=$(curl -H "Host: no-waf.example.com" -sS --no-buffer --connect-timeout "${CONNECT_TIMEOUT}" --max-time "${MAX_TIME}" "${TARGET_URL}" \
  | sed -n 's/^data: //p')

# check number of received lines
LINES_CAPTURED=$(printf "%s" "${DATA_OUT}" | grep -c "." || true)
if [ "${LINES_CAPTURED}" -lt 4 ]; then
  echo "[ERROR] Expected at least 2 SSE data lines, got ${LINES_CAPTURED}. Raw output:"
  printf '%s\n' "${DATA_OUT}"
  exit 2
fi

# check each line contains data
BAD=0
INDEX=0
while IFS= read -r line; do
  INDEX=$((INDEX+1))
  echo "[INFO] Event ${INDEX}: ${line}"
  if ! printf "%s" "${line}" | grep -q "Server time:"; then
    BAD=1
  fi
done <<< "${DATA_OUT}"

if [ "${BAD}" -ne 0 ]; then
  echo "[ERROR] One or more lines did not contain 'Server time:'"
  exit 3
fi

# Now fetch SSE stream via Envoy with a WAF
echo "[INFO] Connecting to SSE stream ${TARGET_URL} (with coraza) and capturing at least 4 events..."
#curl -H "Host: no-waf.example.com"  -sS --no-buffer  --connect-timeout "${CONNECT_TIMEOUT}" --max-time "${MAX_TIME}" "${TARGET_URL}" -v

DATA_OUT=$(curl -H "Host: bar.example.com" -sS --no-buffer --connect-timeout "${CONNECT_TIMEOUT}" --max-time "${MAX_TIME}" "${TARGET_URL}" \
  | sed -n 's/^data: //p')

# check number of received lines
LINES_CAPTURED=$(printf "%s" "${DATA_OUT}" | grep -c "." || true)
if [ "${LINES_CAPTURED}" -lt 4 ]; then
  echo "[ERROR] Expected at least 2 SSE data lines, got ${LINES_CAPTURED}. Raw output:"
  printf '%s\n' "${DATA_OUT}"
  exit 2
fi

# check each line contains data
BAD=0
INDEX=0
while IFS= read -r line; do
  INDEX=$((INDEX+1))
  echo "[INFO] Event ${INDEX}: ${line}"
  if ! printf "%s" "${line}" | grep -q "Server time:"; then
    BAD=1
  fi
done <<< "${DATA_OUT}"

if [ "${BAD}" -ne 0 ]; then
  echo "[ERROR] One or more lines did not contain 'Server time:'"
  exit 3
fi


echo "[SUCCESS] SSE endpoint streamed valid events via Envoy. Test passed."
