# Copyright 2022 The OWASP Coraza contributors
# Copyright © 2023 Axkea, spacewander
# Copyright © 2025 United Security Providers AG, Switzerland
# SPDX-License-Identifier: Apache-2.0

FROM curlimages/curl
USER root

WORKDIR /workspace

RUN apk add --no-cache bash

COPY ./e2e-example.sh /workspace/e2e-example.sh


ENV ENVOY_HOST=envoy:8081
ENV HTTPBIN_HOST=httpbin:8080

CMD ["bash","-c", "/workspace/e2e-example.sh"]
