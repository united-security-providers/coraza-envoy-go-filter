ARG BASE_IMAGE
FROM ${BASE_IMAGE:-scratch}

COPY build/coraza-waf.so /coraza-waf.so
