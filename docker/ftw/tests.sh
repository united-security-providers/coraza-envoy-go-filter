#!/bin/sh
# Copyright 2022 The OWASP Coraza contributors
# Copyright © 2023 Axkea, spacewander
# Copyright © 2025 United Security Providers AG, Switzerland
# SPDX-License-Identifier: Apache-2.0

cd /workspace

# Copied from https://github.com/jcchavezs/modsecurity-wasm-filter-e2e/blob/master/tests.sh

step=1
total_steps=1
max_retries=15 #seconds for the server reachability timeout
host=${1:-envoy}
health_url="http://${host}:8090"

# Testing if the server is up
echo "[$step/$total_steps] Testing application reachability"
status_code="000"
while [[ "$status_code" -eq "000" ]]; do
  status_code=$(curl --write-out "%{http_code}" --silent --output /dev/null $health_url)
  sleep 1
  echo -ne "[Wait] Waiting for response from $health_url. Timeout: ${max_retries}s   \r"
  let "max_retries--"
  if [[ "$max_retries" -eq 0 ]] ; then
    echo "[Fail] Timeout waiting for response from $health_url, make sure the server is running."
#    echo "Envoy Logs:" && cat /etc/envoy/logs/envoy.log
    exit 1
  fi
done
echo -e "\n[Ok] Got status code $status_code, expected 200. Ready to start."

FTW_CLOUDMODE=${FTW_CLOUDMODE:-false}

FTW_INCLUDE=$([ "${FTW_INCLUDE}" == "" ] && echo "" || echo "-i ${FTW_INCLUDE}")

# add --fail-fast to exit on first failed test
# to run only one test add -i <test> e.g. -i 920100-1
/ftw run -d ./coreruleset/tests/regression/tests/ --config ftw.yml --overrides overrides.yml --read-timeout=10s --cloud=$FTW_CLOUDMODE $FTW_INCLUDE  || exit 1
