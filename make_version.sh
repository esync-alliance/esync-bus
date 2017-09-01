#!/bin/sh

set -e
out="$(mktemp)"

cat >"$out" << _EOF_

#ifndef BUILD_VERSION
#define BUILD_VERSION "$(git describe --dirty --exact-match --all --long)"
#endif

_EOF_

diff -q "$out" xl4bus_version.h || {
    cp -f "$out" xl4bus_version.h || true
}

rm -f "$out"

