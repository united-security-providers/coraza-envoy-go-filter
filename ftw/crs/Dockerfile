# Copyright 2022 The OWASP Coraza contributors
# SPDX-License-Identifier: Apache-2.0

FROM ghcr.io/coreruleset/go-ftw:1.3.0

RUN sed -i 's/https/http/' /etc/apk/repositories

RUN apk update && apk add curl

WORKDIR /workspace

# Download CRS
ADD https://github.com/coreruleset/coreruleset/archive/refs/tags/v4.9.0.tar.gz /workspace/coreruleset/
RUN cd coreruleset && tar -xf v4.9.0.tar.gz --strip-components 1

# patch to use HTTP/1.1 instead of HTTP/1.0
RUN  cd coreruleset/tests/regression/tests/ && find .  -type f -name '*.yaml' -exec sed -i 's/HTTP\/1.0/HTTP\/1.1/g' {} \;

COPY ./crs/ftw.yml /workspace/ftw.yml
COPY ./crs/overrides.yml /workspace/overrides.yml
COPY ./crs/tests.sh /workspace/tests.sh

RUN chmod +x /workspace/tests.sh

ENTRYPOINT ["sh"]
CMD ["-c", "/workspace/tests.sh"]
