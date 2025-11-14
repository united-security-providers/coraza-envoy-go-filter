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

# sse_check_stream connects the given URL and checks that at least N events are received and verifies each event contains
# a string in the data: field
# $1: URL to connect to
# $2: Expected number of received lines
# $3: Time to receive events in seconds
# $4: Expected string in the events data field
# $5-N: The rest of the arguments will be passed to the curl command as additional arguments
#       to customize the HTTP call.
function sse_check_stream() {
  local url=${1}
  local expected=${2}
  local connection_time=${3}
  local pattern=${4}
  local args=("${@:3}" --silent)
  echo "   [Info] Connecting to SSE stream ${target_url} and capturing at least ${expected} events"
  local data_out
  data_out=$(curl --no-buffer --connect-timeout "${CONNECT_TIMEOUT}" --max-time "${connection_time}" "${args[@]}" "${url}" \
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
    echo "   [Info] Event ${index}: ${line}"
    if ! printf "%s" "${line}" | grep -q "${pattern}"; then
      bad=1
    fi
  done <<< "${data_out}"

  if [[ "${bad}" -ne 0 ]]; then
    echo "[Fail] One or more lines did not contain '${pattern}'"
    exit 3
  fi
  echo "[Ok] Received ${lines_captured} valid SSE events"
}

# sse_check_exact connects to the given URL and checks that at exactly N events are received and each event contains
# a string in the data: field
# $1: URL to connect to
# $2: Expected number of received lines
# $3: Expected string in the events data field
# $4-N: The rest of the arguments will be passed to the curl command as additional arguments
#       to customize the HTTP call.
function sse_check_exact() {
  local url=${1}
  local expected=${2}
  local pattern=${3}
  local args=("${@:4}" --silent)
  echo "   [Info] Connecting to SSE stream ${url} and expecting exactly ${expected} events"
  local data_out
  data_out=$(curl --no-buffer --connect-timeout "${CONNECT_TIMEOUT}" "${args[@]}" "${url}" \
    | sed -n 's/^data: //p')

  local lines_captured
  lines_captured=$(printf "%s" "${data_out}" | grep -c "." || true)
  if [[ "${lines_captured}" -ne ${expected} ]]; then
    echo "[Fail] Expected at least ${expected} SSE data lines, got ${lines_captured}. Raw output:"
    printf '%s\n' "${data_out}"
    exit 2
  fi

  local bad=0
  local index=0
  while IFS= read -r line; do
    index=$((index+1))
    echo "   [Info] Event ${index}: ${line}"
    if ! printf "%s" "${line}" | grep -q "${pattern}"; then
      bad=1
    fi
  done <<< "${data_out}"

  if [[ "${bad}" -ne 0 ]]; then
    echo "[Fail] One or more lines did not contain 'Server time:'"
    exit 3
  fi
  echo "[Ok] Received ${lines_captured} valid SSE events"
}