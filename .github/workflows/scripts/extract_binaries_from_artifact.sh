#!/bin/bash

set -eu -o pipefail
set -x

TMPDIR=$(mktemp -d)
cleanup() {
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

REPODIR=$(git rev-parse --show-toplevel)
TAG=${TAG:-$(git log -n1 --pretty=%h)}
BINDIR="${REPODIR}/bin"
ARTIFACTSDIR="${REPODIR}/artifacts"

PLATFORM=${1}
ARCH=${2}

ARTIFACT="${ARTIFACTSDIR}/spire-${TAG}-${PLATFORM}-${ARCH}.zip"
EXTRAS_ARTIFACT="${ARTIFACTSDIR}/spire-extras-${TAG}-${PLATFORM}-${ARCH}.zip"

unzip -j "${ARTIFACT}" "spire-${TAG}/bin/*" -d bin
unzip -j "${EXTRAS_ARTIFACT}" "spire-extras-${TAG}/bin/*" -d "${BINDIR}"

