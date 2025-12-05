#!/bin/bash
# Copyright © 2025 United Security Providers AG, Switzerland
# SPDX-License-Identifier: Apache-2.0
#
# shared functions accross e2e test scripts

function util_hello() {
  echo "hello"
}

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

# check_status sends HTTP requests to the given URL and expects a given response code.
# $1: The URL to send requests to.
# $2: The expected status code.
# $3-N: The rest of the arguments will be passed to the curl command as additional arguments
#       to customize the HTTP call.
function check_status() {
    local url=${1}
    local status=${2}
    local args=("${@:3}" --write-out '%{http_code}' --silent --output /dev/null)
    status_code=$(curl --connect-timeout "${CONNECT_TIMEOUT}" "${args[@]}" "${url}")
    if [[ "${status_code}" -ne ${status} ]] ; then
      echo "[Fail] Unexpected response with code ${status_code} from ${url}"
      exit 1
    fi
    echo "[Ok] Got status code ${status_code}, expected ${status}"
}

# check_body sends the given HTTP request and checks the response body.
# $1: The URL to send requests to.
# $2: true/false indicating if an empty, or null body is expected or not.
# $3-N: The rest of the arguments will be passed to the curl command as additional arguments
#       to customize the HTTP call.
function check_body() {
    local url=${1}
    local empty=${2}
    local args=("${@:3}" --silent)
    response_body=$(curl --connect-timeout "${CONNECT_TIMEOUT}" "${args[@]}" "${url}")
    if [[ "${empty}" == "true" ]] && [[ -n "${response_body}" ]]; then
      echo -e "[Fail] Unexpected response with a body. Body dump:\n${response_body}"
      exit 1
    fi
    if [[ "${empty}" != "true" ]] && [[ -z "${response_body}" ]]; then
      echo -e "[Fail] Unexpected response with a body. Body dump:\n${response_body}"
      exit 1
    fi
    echo "[Ok] Got response with an expected body (empty=${empty})"
}

# sse_check_stream connects the given URL and checks that at least N events are received, verifies each event contains
# a string in the data: field, and each arrives at ~1s, 2s, 3s, etc. from request start
# $1: URL to connect to
# $2: Expected number of received lines
# $3: Time to receive events in seconds
# $4: Expected string in the events data field
# $5-N: The rest of the arguments will be passed to the curl command as additional arguments
#       to customize the HTTP call.
function sse_check_stream() {
  local url=$1
  local expected=$2
  local connection_time=$3
  local pattern=$4
  shift 4
  local args=("$@" --silent --no-buffer --connect-timeout "$CONNECT_TIMEOUT" --max-time "$connection_time")

  local start_time=$(date +%s.%N)
  echo "   [Info] Connecting to SSE stream ${url}"

  local lines_captured=0
  local bad=0

  # Read SSE events line-by-line from curl stream
  while IFS= read -r line; do
    if [[ $line =~ ^data:\ (.*) ]]; then
      local data="${BASH_REMATCH[1]}"
      local receive_time=$(date +%s.%N)
      local elapsed=$(echo "$receive_time - $start_time" | bc -l)
      local elapsed_rounded=$(printf "%.3f" $elapsed)

      lines_captured=$((lines_captured + 1))
      echo "   > [Info] Event ${lines_captured}: ${data}      (elapsed=${elapsed_rounded}s)"

      # Check pattern
      if ! [[ "$data" =~ $pattern ]]; then
        echo "   > [Fail] Event ${lines_captured} does not match pattern: '${pattern}'"
        ((bad += 1))
      fi

      # Validate event N arrives close to N seconds after start with +/- 200ms tolerance
      local expected_time=$(echo "${lines_captured} - 0.2" | bc -l)
      local max_time=$(echo "${lines_captured} + 0.2" | bc -l)

      if (( $(echo "$elapsed < $expected_time" | bc -l) )) || (( $(echo "$elapsed > $max_time" | bc -l) )); then
        echo "   > [Fail] Event ${lines_captured} arrived at ${elapsed_rounded}s (expected between ${expected_time}s and ${max_time}s)"
        ((bad += 1))
      else
        echo "   > [Ok] Event ${lines_captured} arrived between ${expected_time}s and ${max_time}s"

      fi

    fi

    (( lines_captured >= expected )) && break
  done < <(curl "${args[@]}" "${url}")

  # Final checks
  if (( lines_captured < expected )); then
    echo "[Fail] Expected ${expected} events, got ${lines_captured}"
    exit 2
  fi
  if (( bad != 0 )); then
    echo "[Fail] ${bad} event validation checks failed."
    exit 3
  fi

  echo "[Success] Received ${lines_captured} events with correct timing and content"
}

# sse_check_exact connects to the given URL and checks that exactly N events are received,
# each contains a pattern, and each arrives at ~1s, 2s, 3s, etc. from request start
# $1: URL to connect to
# $2: Expected number of received lines
# $3: Expected string in the events data field
# $4-N: Additional curl arguments
function sse_check_exact() {
  local url=$1
  local expected=$2
  local pattern=$3
  shift 3
  local args=("$@" --silent --no-buffer --connect-timeout "$CONNECT_TIMEOUT" --max-time "$((expected + 5))")

  local start_time=$(date +%s.%N)
  echo "   [Info] Connecting to SSE stream ${url} and expecting exactly ${expected} events"

  local lines_captured=0
  local bad=0

  # Read SSE events line-by-line from curl stream
  while IFS= read -r line; do
    if [[ $line =~ ^data:\ (.*) ]]; then
      local data="${BASH_REMATCH[1]}"
      local receive_time=$(date +%s.%N)
      local elapsed=$(echo "$receive_time - $start_time" | bc -l)
      local elapsed_rounded=$(printf "%.3f" $elapsed)

      lines_captured=$((lines_captured + 1))
      echo "   > [Info] Event ${lines_captured}: ${data}      (elapsed=${elapsed_rounded}s)"

      # Check pattern
      if ! [[ "$data" =~ $pattern ]]; then
        echo "   > [Fail] Event ${lines_captured} does not match pattern: '${pattern}'"
        ((bad += 1))
      fi

      # Validate timing: event N should arrive close to N seconds after start with +/- 200ms tolerance
      local expected_min=$(echo "${lines_captured} - 0.2" | bc -l)
      local expected_max=$(echo "${lines_captured} + 0.2" | bc -l)

      if (( $(echo "$elapsed < $expected_min" | bc -l) )) || (( $(echo "$elapsed > $expected_max" | bc -l) )); then
        echo "   > [Fail] Event ${lines_captured} arrived at ${elapsed_rounded}s (expected between ${expected_min}s and ${expected_max}s)"
        ((bad += 1))
      else
        echo "   > [Ok] Event ${lines_captured} arrived between ${expected_min}s and ${expected_max}s"
      fi
    fi

    # Exit loop after receiving expected number of events
    (( lines_captured >= expected )) && break
  done < <(curl "${args[@]}" "${url}")

  # Final validation
  if (( lines_captured != expected )); then
    echo "[Fail] Expected exactly ${expected} events, got ${lines_captured}"
    exit 2
  fi

  if (( bad != 0 )); then
    echo "[Fail] ${bad} event validation checks failed."
    exit 3
  fi

  echo "[Success] Received exactly ${lines_captured} events with correct timing and content"
}