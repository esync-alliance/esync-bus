#!/bin/bash -ex

portdir=`pwd`
rootdir=${portdir}/..

#DBG="-g -O0"

# Build json-c:
build_json_c() {
    cd ${rootdir}
    if [ ! -f "json-c/.git" ]; then
        git submodule update json-c
    fi
    rm -rf json-c-build
    cp -fr json-c json-c-build
    pushd json-c-build
    autoreconf -f -i
    CFLAGS="-fPIC -fvisibility=hidden -Wno-implicit-fallthrough" \
    CPPFLAGS="-include $(pwd)/../json-c-rename.h" \
    ./configure --enable-static --disable-shared
    make -j
    popd
}

# Build mbedtls:
build_mbedtls() {
    cd ${rootdir}
    if [ ! -f "mbedtls/.git" ]; then
        git submodule update mbedtls
    fi
    rm -rf mbedtls-build
    cp -fr mbedtls mbedtls-build
    pushd mbedtls-build
    ./scripts/config.pl set MBEDTLS_PLATFORM_MEMORY
    mkdir -p build
    cd build
    cmake -DCMAKE_C_FLAGS="$DBG -fPIC -fvisibility=hidden" ..
    make -j
    popd
}

#Build cjose:
build_cjose() {
    cd ${rootdir}
    if [ ! -f "cjose/.git" ]; then
        git submodule update cjose
    fi
    rm -rf cjose-build
    cp -fr cjose cjose-build
    pushd cjose-build
    autoreconf -f -i
    CFLAGS="$DBG -fPIC -fvisibility=hidden" \
    ./configure --with-openssl=/usr --with-jansson=/usr --enable-static --disable-shared
    make -j
    popd
}

#Build c-ares:
build_cares() {
    cd ${rootdir}
    if [ ! -f "c-ares/.git" ]; then
        git submodule update c-ares
    fi
    rm -rf c-ares-build
    cp -fr c-ares c-ares-build
    pushd c-ares-build
    ./buildconf
    CFLAGS="$DBG -fPIC -fvisibility=hidden" \
    ./configure --enable-static --disable-shared
    make -j
    popd
}

if [ "$1" = 'clean' ] ; then
    rm -rf ${rootdir}/json-c-build
    rm -rf ${rootdir}/mbedtls-build
    rm -rf ${rootdir}/cjose-build
    rm -rf ${rootdir}/c-ares-build
    rm ${portdir}/build_deps.done
else
    git submodule init
    build_json_c
    build_mbedtls
    build_cjose
    build_cares
    touch ${portdir}/build_deps.done
fi

echo "Done!"
exit 0
