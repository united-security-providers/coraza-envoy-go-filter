# Copyright 2022 The OWASP Coraza contributors
# Copyright © 2023 Axkea, spacewander
# Copyright © 2025 United Security Providers AG, Switzerland
# SPDX-License-Identifier: Apache-2.0

FROM curlimages/curl
USER root

WORKDIR /workspace

RUN apk add --no-cache bash

COPY ./e2e-base.sh /workspace/e2e-base.sh
COPY ./e2e-sse.sh /workspace/e2e-sse.sh

ENV ENVOY_HOST=envoy:8081 \
    HTTPBIN_HOST=httpbin:8080 \
    SSE_HOST=sse-server:8080 \
    SSE_PATH=/events \
    HEALTH_PATH=/healthz \
    CONNECT_TIMEOUT=5 \
    MAX_TIME=5

# Default runs both tests sequentially: general e2e then SSE. Compose can still override.
CMD ["bash","-lc", "set -e; bash /workspace/e2e-base.sh && bash /workspace/e2e-sse.sh"]