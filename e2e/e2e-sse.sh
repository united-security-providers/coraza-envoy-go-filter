#!/bin/bash
# e2e/e2e-sse.sh — E2E test for SSE endpoint (via Envoy)
#
# This script is intended to run inside the tests container defined in e2e/docker-compose.yml.
# It waits for the SSE server health endpoint to be ready, then connects to Envoy and verifies
# that the SSE endpoint streams at least four messages containing the text "Server time:".
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
:[[ "${DEBUG}" == "true" ]] && set -x

ENVOY_HOST=${ENVOY_HOST:-envoy:8081}
HTTPBIN_HOST=${HTTPBIN_HOST:-httpbin:8080}
SSE_HOST=${SSE_HOST:-sse-server:8080}
SSE_PATH=${SSE_PATH:-/events}
HEALTH_PATH=${HEALTH_PATH:-/healthz}
CONNECT_TIMEOUT=${CONNECT_TIMEOUT:-5}
MAX_TIME=${MAX_TIME:-15}

health_url="http://${SSE_HOST}${HEALTH_PATH}"
target_url="http://${ENVOY_HOST}${SSE_PATH}"

# wait_for_service waits until the given URL returns a 200 status code.
# $1: The URL to send requests to.
# $2: The max number of requests to send before giving up.
function wait_for_service() {
  local status_code="000"
  local url=${1}
  local max=${2}
  while [[ "${status_code}" -ne "200" ]]; do
    status_code=$(curl --connect-timeout "${CONNECT_TIMEOUT}" --write-out "%{http_code}" --silent --output /dev/null "${url}")
    sleep 1
    echo -ne "[Wait] Waiting for response from ${url}. Timeout: ${max}s   \r"
    ((max-=1))
    if [[ "${max}" -eq 0 ]]; then
      echo "[Fail] Timeout waiting for response from ${url}, make sure the server is running."
      exit 1
    fi
  done
  echo -e "\n[Ok] Got status code ${status_code}"
}

# sse_check checks that at least n data lines are received and each contains "Server time:"
# $1: Host header value
# $2: Expected number of received lines
# $3: Time to receive events in seconds
# $2: Human-friendly label for the step (e.g., "without WAF", "with WAF")
function sse_check() {
  local host_header=${1}
  local expected=${2}
  local connection_time=${3}
  local label=${4}
  echo "[Info] Connecting to SSE stream ${target_url} (${label}) and capturing at least ${expected} events"
  local data_out
  data_out=$(curl -H "Host: ${host_header}" -sS --no-buffer --connect-timeout "${CONNECT_TIMEOUT}" --max-time "${connection_time}" "${target_url}" \
    | sed -n 's/^data: //p')

  local lines_captured
  lines_captured=$(printf "%s" "${data_out}" | grep -c "." || true)
  if [[ "${lines_captured}" -lt ${expected} ]]; then
    echo "[Fail] Expected at least ${expected} SSE data lines, got ${lines_captured}. Raw output:"
    printf '%s\n' "${data_out}"
    exit 2
  fi

  local bad=0
  local index=0
  while IFS= read -r line; do
    index=$((index+1))
    echo "[Info] Event ${index}: ${line}"
    if ! printf "%s" "${line}" | grep -q "Server time:"; then
      bad=1
    fi
  done <<< "${data_out}"

  if [[ "${bad}" -ne 0 ]]; then
    echo "[Fail] One or more lines did not contain 'Server time:'"
    exit 3
  fi
  echo "[Ok] Received ${lines_captured} valid SSE events (${label})"
}

step=1
# 3 main steps: reachability, SSE without WAF, SSE with WAF
total_steps=3

# Step 1: Testing application reachability (SSE health)
echo "[${step}/${total_steps}] Testing SSE server reachability"
wait_for_service "${health_url}" 15

# Step 2: SSE via Envoy without WAF
((step+=1))
echo "[${step}/${total_steps}] Testing SSE streaming (without WAF)"
sse_check "no-waf.example.com" 4 $MAX_TIME "without WAF"

# Step 3: SSE via Envoy with WAF
((step+=1))
echo "[${step}/${total_steps}] Testing SSE streaming (with WAF)"
sse_check "bar.example.com" 4 $MAX_TIME "with WAF"

echo "[Ok] SSE endpoint streamed valid events via Envoy."
echo "[Done] All tests passed"