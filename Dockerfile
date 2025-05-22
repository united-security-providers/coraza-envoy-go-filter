ARG BASE_IMAGE
FROM ${BASE_IMAGE:-scratch}

COPY coraza-waf.so /coraza-waf.so
