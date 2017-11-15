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
    wget https://c-ares.haxx.se/download/c-ares-1.13.0.tar.gz --no-check-certificate
    tar -xvzf ./c-ares-1.13.0.tar.gz
    mv ./c-ares-1.13.0 ./c-ares
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
    cmake -DENABLE_TESTING=OFF -DCMAKE_C_FLAGS="-fPIC -fvisibility=hidden" ..
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
    ed config.status < ../../cross_compile_scripts/jsonced
    make
    cd ..
    touch jsonc.ok
    cp -fr json-c ../json-c-build
fi

