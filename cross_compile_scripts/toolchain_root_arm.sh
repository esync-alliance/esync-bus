#!/bin/sh

set -e

TCR=${HOME}/tmp/linaro

if test -n "$USE_ARM_TOOLCHAIN"; then
    TCR="$USE_ARM_TOOLCHAIN"
fi

TCH=arm-linux-gnueabi
TCP="${TCR}/bin/${TCH}-"
export CPP=${TCP}cpp
export AR=${TCP}ar
export AS=${TCP}as
export NM=${TCP}nm
export CC=${TCP}gcc 
export CXX=${TCP}g++
export LD=${TCP}ld
export RANLIB=${TCP}ranlib
export MAKEFLAGS=-j
export SYSROOT="${TCR}/sysroot"
export USR="${SYSROOT}/usr"
export PKG_CONFIG_PATH=${USR}/lib/pkgconfig

mkdir -p arm_src
cd arm_src

#** ares

if test ! -f cares.ok; then
    rm -rf c-ares
    proxychains git clone https://github.com/c-ares/c-ares.git
    cd c-ares
    autoreconf -f -i
    ./configure --prefix=$USR --host=$TCH
    make install
    cd ..
    touch cares.ok
fi

#** openssl

if test ! -f openssl.ok; then
    rm -rf openssl
    git clone https://github.com/openssl/openssl.git
    cd openssl
    git checkout OpenSSL_1_0_2k
    ./config --prefix=$USR
    ./Configure dist -fPIC --prefix=$USR
    make -j1 install
    cd ..
    touch openssl.ok
fi

#** jansson

if test ! -f jansson.ok; then
    rm -rf jansson
    git clone https://github.com/akheron/jansson.git
    cd jansson
    autoreconf -f -i
    ./configure --prefix=$USR --host=$TCH
    make install
    cd ..
    touch jansson.ok
fi

#** cjose

if test ! -f cjose.ok; then
    rm -rf cjose
    git clone https://github.com/veselov/cjose
    cd cjose
    git checkout json_ser
    autoreconf -f -i
    CFLAGS="-fPIC -fvisibility=hidden" ./configure --prefix=$USR --host=$TCH --with-openssl=$USR --with-jansson=$USR --enable-static --disable-shared
    make
    cd ..
    touch cjose.ok
    cp -fr cjose ../cjose-build
fi

#** mbedtls

if test ! -f mbedtls.ok; then
    rm -rf mbedtls
    git clone https://github.com/ARMmbed/mbedtls.git
    cd mbedtls
    git checkout 45d269555b3cb9785a75e804fe74413baffd4f0a
    ./scripts/config.pl set MBEDTLS_PLATFORM_MEMORY
    mkdir -p build && cd build
    cmake -DCMAKE_C_FLAGS="-fPIC -fvisibility=hidden" ..
    make
    cd ../..
    touch mbedtls.ok
    cp -fr mbedtls ../mbedtls-build
fi

#** json-c

if test ! -f jsonc.ok; then
    rm -rf json-c
    git clone https://github.com/json-c/json-c.git
    cd json-c
    git checkout json-c-0.12-20140410
    autoreconf -f -i
    CFLAGS="-fPIC -fvisibility=hidden -Wno-error" CPPFLAGS="-include $(pwd)/../../json-c-rename.h" ./configure --prefix=$USR --host=$TCH --enable-static --disable-shared
# AC_FUNC_MALLOC fails
    ed config.status < ../../arm_scripts/jsonced
    make
    cd ..
    touch jsonc.ok
    cp -fr json-c ../json-c-build
fi

