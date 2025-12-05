FROM envoyproxy/envoy:contrib-dev AS build

ARG BUILD_TAGS

RUN apt update && apt install -y libtool autoconf make libre2-dev golang-1.23-go curl tar python3
RUN mkdir /libinjection && \
    curl -L https://github.com/libinjection/libinjection/archive/4aa3894b21d03d9d8fc364505c0617d2aca73fc1.tar.gz | tar -xz --strip-components 1 -C /libinjection && \
    cd /libinjection && \
    autoreconf -i --force && \
    ./configure && \
    make install
WORKDIR /src
COPY internal ./internal
COPY main.go go.mod go.sum .
RUN /usr/lib/go-1.23/bin/go build -o coraza-waf.so -buildmode=c-shared -tags=$BUILD_TAGS .

ENTRYPOINT ["/usr/bin/cp", "/src/coraza-waf.so", "/build"]

FROM envoyproxy/envoy:contrib-dev AS envoy
COPY --from=build /usr/lib/libinjection.so* /usr/lib/
COPY --from=build /src/coraza-waf.so /etc/envoy/coraza-waf.so
RUN apt update && apt install -y libre2-9
