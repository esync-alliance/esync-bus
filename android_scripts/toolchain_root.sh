#!/bin/sh

set -e

TCR=${HOME}/tmp/arm-23

if test -n "$USE_ANDROID_TOOLCHAIN"; then
    TCR="$USE_ANDROID_TOOLCHAIN"
fi

TCH=arm-linux-androideabi
TCP="${TCR}/bin/${TCH}-"
export CPP=${TCP}cpp
export AR=${TCP}ar
export AS=${TCP}as
export NM=${TCP}nm
export CC=${TCP}gcc 
export CXX=${TCP}g++
export LD=${TCP}ld
export RANLIB=${TCP}ranlib
export PKG_CONFIG_PATH=${TCR}/lib/pkgconfig
export MAKEFLAGS=-j
export SYSRT="${TCR}/sysroot"
export USR="${SYSRT}/usr"

mkdir -p android_src
cd android_src

#** ares

if test ! -f cares.ok; then
    rm -rf c-ares
    git clone https://github.com/c-ares/c-ares.git
    cd c-ares
    autoreconf -f -i
    ./configure --prefix=$USR --host=$TCH --enable-static=yes --enable-shared=no
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
    ./Configure android --prefix=$USR no-shared
    make -j1
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
    ./configure --prefix=$USR --host=$TCH --enable-static=yes --enable-shared=no
    make install
    cd ..
    touch jansson.ok
fi

#** cjose

if test ! -f cjose.ok; then
    rm -rf cjose
    git clone https://github.com/cisco/cjose.git
    cd cjose
    autoreconf -f -i
    ./configure --prefix=$USR --host=$TCH --enable-static=yes --enable-shared=no
    make install
    cd ..
    touch cjose.ok
fi

#** json-c

if test ! -f jsonc.ok; then
    rm -rf json-c
    git clone https://github.com/json-c/json-c.git
    cd json-c
    git checkout acbcc062f9c114f7b2a63b792897fdfffed71d14
    autoreconf -f -i
    CFLAGS="-fPIC -fvisibility=hidden -Wno-error" CPPFLAGS="-include $(pwd)/../../json-c-rename.h" ./configure --prefix=$USR --host=$TCH --enable-static --disable-shared
    # AC_FUNC_MALLOC fails
    ed config.status < ../../android_scripts/jsonced
    make
    cd ..
    touch jsonc.ok
    cp -fr json-c ../json-c-build
fi

