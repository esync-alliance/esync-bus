#!/bin/bash

CWD=$(pwd)
LIB_XL4BUS_DIR="${CWD}/.."

export LIBXL4BUS_PORT=ghs_port

git submodule init
git submodule update

JSONC_GHS="${CWD}/json-c"
CJOSE_GHS="${CWD}/cjose"
MBEDTLS_GHS="${CWD}/mbedtls"
JANSSON_GHS="${CWD}/jansson"
CARES_GHS="${CWD}/c-ares"
OPENSSL_GHS="${CWD}/openssl"
GHS_MISC="${CWD}/ghs_misc"

build_lib()
{
    build_dir="$1/build"

    [ ! -d "${build_dir}" ] && mkdir -p $build_dir
    cd $build_dir
    cmake .. && make
}

dirs=($JSONC_GHS $MBEDTLS_GHS $JANSSON_GHS $CARES_GHS $OPENSSL_GHS $GHS_MISC $CJOSE_GHS)
for dir in "${dirs[@]}"; do
    build_lib $dir
done

# Build libxl4bus and broker for GHS
cd $LIB_XL4BUS_DIR
rm -rf build
mkdir build && cd build
cmake ..
make
cd $CWD
