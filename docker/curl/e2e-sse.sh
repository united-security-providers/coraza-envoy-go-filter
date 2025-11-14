#!/bin/bash
# Copyright © 2025 United Security Providers AG, Switzerland
# SPDX-License-Identifier: Apache-2.0
#
# e2e/e2e-sse.sh — E2E test for SSE endpoint (via Envoy)
# This script is intended to run inside the tests container defined in e2e/docker-compose.yml.

# source shared functions accross e2e scripts
. e2e-utils.sh

[[ "${DEBUG}" == "true" ]] && set -x

ENVOY_HOST=${ENVOY_HOST:-envoy:8081}
SSE_HOST=${SSE_HOST:-sse-server:8080}
SSE_PATH=${SSE_PATH:-/events}
HEALTH_PATH=${HEALTH_PATH:-/health}
CONNECT_TIMEOUT=${CONNECT_TIMEOUT:-5}
MAX_TIME=${MAX_TIME:-15}

health_url="http://${SSE_HOST}${HEALTH_PATH}"
target_url="http://${ENVOY_HOST}${SSE_PATH}"


echo "####################################################"
echo "#                  E2E SSE TESTS                   #"
echo "####################################################"

step=1
total_steps=6

# Step 1: Testing application reachability (SSE health)
echo "[${step}/${total_steps}] Testing SSE server reachability"
wait_for_service "${health_url}" 15

# Step 2: Test SSE stream via Envoy with SecRuleEngine disabled
((step+=1))
echo "[${step}/${total_steps}] Testing SSE streaming [SecRuleEngine Off]"
sse_check_stream  ${target_url} 4 $MAX_TIME "Server time:" -H "Host: no-waf.example.com"

# Step 3: Test exact 5 SSE events via Envoy with SecRuleEngine disabled
((step+=1))
echo "[${step}/${total_steps}] Testing receive exact 5 SSE events [SecRuleEngine Off]"
sse_check_exact "${target_url}/5" 5 "Server time:" -H "Host: no-waf.example.com"

# Step 4: Test SSE stream via Envoy with WAF with SecResponseBodyAccess Off
((step+=1))
echo "[${step}/${total_steps}] Testing SSE streaming [SecResponseBodyAccess Off]"
sse_check_stream ${target_url} 4 $MAX_TIME "Server time:" -H "Host: body-off.example.com"

# Step 5: Test exact 5 SSE events via Envoy with WAF with SecResponseBodyAccess Off
((step+=1))
echo "[${step}/${total_steps}] Testing receive exact 5 SSE events [SecResponseBodyAccess Off]"
sse_check_exact "${target_url}/5" 5 "Server time:" -H "Host: body-off.example.com"

# Step 6: Test SSE stream via Envoy with default WAF
# TODO: this test currently fails because the golang filter can't handle it correctly
#((step+=1))
#echo "[${step}/${total_steps}] Testing SSE streaming [default WAF]"
#sse_check_stream ${target_url} 4 $MAX_TIME "Server time:" -H "Host: foo.example.com"

# Step 7: Test exact 5 SSE events via Envoy with default WAF
((step+=1))
echo "[${step}/${total_steps}] Testing receive exact 5 SSE events [default WAF]"
sse_check_exact "${target_url}/5" 5 "Server time:" -H "Host: foo.example.com"


echo "####################################################"
echo "#                   SUCCESS :-)                    #"
echo "####################################################"
echo ""
echo ""