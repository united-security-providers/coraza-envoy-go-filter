# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0
ARG CRS_VERSION=4.25.0
ARG FTW_VERSION=2.1.0
ARG FTW_CONFIG
ARG FTW_OVERRIDES

FROM ghcr.io/coreruleset/go-ftw:${FTW_VERSION}
ARG CRS_VERSION
ARG FTW_CONFIG
ARG FTW_OVERRIDES

RUN sed -i 's/https/http/' /etc/apk/repositories

RUN apk update && apk add curl

WORKDIR /workspace

# Download CRS
ADD https://github.com/coreruleset/coreruleset/archive/refs/tags/v${CRS_VERSION}.tar.gz /workspace/coreruleset/
RUN cd coreruleset && tar -xf v${CRS_VERSION}.tar.gz --strip-components 1

COPY ./${FTW_CONFIG} /workspace/ftw.yml
COPY ./${FTW_OVERRIDES} /workspace/overrides.yml
COPY ./tests.sh /workspace/tests.sh

RUN chmod +x /workspace/tests.sh

ENTRYPOINT ["sh"]
CMD ["-c", "/workspace/tests.sh"]
