#!/bin/bash

set -eu

if [ $# -eq 0 ]; then
    echo "Error: Version argument required"
    echo
    echo "Usage: update_crs.sh <VERSION>"
    exit 1
fi


VERSION="$1"
if [[ -z "$VERSION" ]]; then
    echo "Version cannot be an empty string"
    exit 1
fi
VERSION_WITHOUT_PREFIX="${VERSION#v}"
VERSION_WITH_PREFIX="v${VERSION_WITHOUT_PREFIX}"

CRS_NAME_VERSION="coreruleset-${VERSION_WITH_PREFIX}"
TMP_CRS_DIRECTORY="/tmp/coreruleset-${VERSION_WITHOUT_PREFIX}"

rm -rf "${TMP_CRS_DIRECTORY}"
curl -L "https://github.com/coreruleset/coreruleset/archive/v${VERSION}/${CRS_NAME_VERSION}.tar.gz" | tar xz -C "/tmp"
rm -f internal/config/rules/crs/*
cp "${TMP_CRS_DIRECTORY}/rules"/* internal/config/rules/crs/

echo "Now you can update the used CRS version in the FTW tests under tests/ftw/Dockerfile"
