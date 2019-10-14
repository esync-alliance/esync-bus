#!/bin/bash -e

portdir=$(cd $(dirname "$0") && pwd);
projdir=${portdir}/..

jansson_commit_id="6dddf687d84306ea5d4ff9b13a28dc22282c77e6"
cjose_commit_id="b122181f5537e928f8e78afd33f96a35bdefa67f"
mbedtls_commit_id="6c34268e203d23bbfbfda3f7362dac8b9b9382bc"
json_commit_id="985c46fec39d1d3043f98e8d8cdb9d040131b3bb"
cares_commit_id="17dc1b3102e0dfc3e7e31369989013154ee17893"

#
# Build jansson library
#
build_jansson()
{
    if [ "$1" = "clean" ]; then
        rm -rf ${projdir}/jansson-build
        return 0
    fi

    if [ ! -d ${projdir}/jansson-build ]; then
        cp -rf ${projdir}/jansson ${projdir}/jansson-build
        cd ${projdir}/jansson-build
        git apply ${portdir}/deps/jansson.patch
    fi

    echo "Building jansson library..."

    cd ${projdir}/jansson-build

    if [ "$(git rev-parse HEAD)" != "$jansson_commit_id" ]; then
        echo "Wrong commit id, expected $jansson_commit_id"
    fi

    if [ ! -d build ]; then
        mkdir build && cd build
        cmake -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_TOOLCHAIN_FILE=${portdir}/cmake/${toolchain} \
              -DJANSSON_BUILD_SHARED_LIBS=ON ..
    else
        cd build
    fi

    make -j
}

#
# Build cjose library
#
build_cjose()
{
    if [ "$1" = "clean" ]; then
        rm -rf ${projdir}/cjose-build
        return 0
    fi

    if [ ! -d ${projdir}/cjose-build ]; then
        cp -rf ${projdir}/cjose ${projdir}/cjose-build
        cd ${projdir}/cjose-build
        git apply ${portdir}/deps/cjose.patch
    fi

    echo "Building cjose library..."

    cd ${projdir}/cjose-build

    if [ "$(git rev-parse HEAD)" != "$cjose_commit_id" ]; then
        echo "Wrong commit id, expected $cjose_commit_id"
    fi

    export WITH_JANSSON=${projdir}/jansson-build/build
    autoreconf -f -i
    ./configure --host=${am_host} --with-openssl=${QNX_TARGET} -with-jansson=${WITH_JANSSON} --enable-static --disable-shared

    if [ "$XL4_TARGET_OS" = "qnx660" ]; then
        make -j CFLAGS='-fPIC -fvisibility=hidden'
    else
        make -j CFLAGS='-std=gnu99 -fPIC -fvisibility=hidden'
    fi
}

#
# Build mbedtls library
#
build_mbedtls()
{
    if [ "$1" = "clean" ]; then
        rm -rf ${projdir}/mbedtls-build
        return 0
    fi

    if [ ! -d ${projdir}/mbedtls-build ]; then
        cp -rf ${projdir}/mbedtls ${projdir}/mbedtls-build
        cd ${projdir}/mbedtls-build
        git apply ${portdir}/deps/mbedtls.patch
        ./scripts/config.pl set MBEDTLS_PLATFORM_MEMORY
    fi

    echo "Building mbedtls library..."

    cd ${projdir}/mbedtls-build

    if [ "$(git rev-parse HEAD)" != "$mbedtls_commit_id" ]; then
        echo "Wrong commit id, expected $mbedtls_commit_id"
    fi

    if [ ! -d build ]; then
        mkdir build && cd build
        cmake -DCMAKE_BUILD_TYPE=Release \
              -DCMAKE_TOOLCHAIN_FILE=${portdir}/cmake/${toolchain} \
              -DCMAKE_C_FLAGS="-fPIC -fvisibility=hidden" \
              -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF ..
    else
        cd build
    fi

    make -j
}

#
# Build json-c library
#
build_json_c()
{
    if [ "$1" = "clean" ]; then
        rm -rf ${projdir}/json-c-build
        return 0
    fi

    if [ ! -d ${projdir}/json-c-build ]; then
        cp -rf ${projdir}/json-c ${projdir}/json-c-build
        cd ${projdir}/json-c-build
        git apply ${portdir}/deps/json-c.patch
    fi

    echo "Building json-c library..."

    cd ${projdir}/json-c-build

    if [ "$(git rev-parse HEAD)" != "$json_commit_id" ]; then
        echo "Wrong commit id, expected $json_commit_id"
    fi

    autoreconf -f -i
    ./configure --host=${am_host} ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes --enable-static --disable-shared

    if [ "$XL4_TARGET_OS" = "qnx660" ]; then
        make -j CFLAGS='-std=gnu99 -fPIC -fvisibility=hidden -Wno-implicit-fallthrough' CPPFLAGS='-include $(PWD)/../json-c-rename.h'
    else
        make -j CFLAGS='-fPIC -fvisibility=hidden -Wno-implicit-fallthrough' CPPFLAGS='-include $(PWD)/../json-c-rename.h'
    fi
}

#
# Build c-ares library
#
build_c_ares()
{
    if [ "$1" = "clean" ]; then
        rm -rf ${projdir}/c-ares-build
        return 0
    fi

    if [ ! -d ${projdir}/c-ares-build ]; then
        cp -rf ${projdir}/c-ares ${projdir}/c-ares-build
        cd ${projdir}/c-ares-build
    fi

    echo "Building c-ares library..."

    cd ${projdir}/c-ares-build

    if [ "$(git rev-parse HEAD)" != "$cares_commit_id" ]; then
        echo "Wrong commit id, expected $cares_commit_id"
    fi

    ./buildconf
    ./configure --host=${am_host} --enable-static --disable-shared
    make -j CFLAGS="-fPIC -fvisibility=hidden"
}

#
# Build all libraries
#
build_all()
{
    build_jansson $1
    build_cjose $1
    build_mbedtls $1
    build_json_c $1
    build_c_ares $1
}

#
# Check supported target os
#
if [ "$XL4_TARGET_OS" != "qnx660" ] && [ "$XL4_TARGET_OS" != "qnx700" ]; then
    echo "Unsupported target operating system ($XL4_TARGET_OS)"
    echo "Please export XL4_TARGET_OS to one of below values:"
    echo "    qnx660"
    echo "    qnx700"
    exit 1
fi

#
# Check supported architect
#
if [ "$XL4_TARGET_ARCH" != "armv7l" ] && [ "$XL4_TARGET_ARCH" != "aarch64l" ]; then
    echo "Unsupported target architecture ($XL4_TARGET_ARCH)"
    echo "Please export XL4_TARGET_ARCH to one of below values:"
    echo "    armv7l"
    echo "    aarch64l"
    exit 1
fi

#
# Check unsupported combination
#
if [ "$XL4_TARGET_OS" = "qnx660" ] && [ "$XL4_TARGET_ARCH" = "aarch64l" ]; then
    echo "Target aarch64l is not supported on qnx660"
    exit 1
fi

#
# Check qnx660 build environment
#
if [ "$XL4_TARGET_OS" = "qnx660" ] && [ "$XL4_TARGET_ARCH" = "armv7l" ]; then
    if [[ "$QNX_TARGET" != *"qnx6"* ]]; then
        echo "Please set qnx660 build environment (XL4_TARGET_OS=qnx660)"
        exit 1
    else
        am_host="arm-unknown-nto-qnx6.6.0eabi"
        toolchain="qnx660_armv7l.cmake"
    fi
fi

#
# Check qnx700 build environment
#
if [ "$XL4_TARGET_OS" = "qnx700" ]; then
    if [[ "$QNX_TARGET" != *"qnx7"* ]]; then
        echo "Please set qnx700 build environment (XL4_TARGET_OS=qnx700)"
        exit 1
    else
        if [ "$XL4_TARGET_ARCH" = "armv7l" ]; then
            am_host="arm-unknown-nto-qnx7.0.0eabi"
            toolchain="qnx700_armv7l.cmake"
        else
            am_host="aarch64-unknown-nto-qnx7.0.0"
            toolchain="qnx700_aarch64l.cmake"
        fi
    fi
fi

#
# Process user input
#
case "$1" in
    ("all")
        build_all $2;;
    ("jansson")
        build_jansson $2 ;;
    ("cjose")
        build_cjose $2 ;;
    ("mbedtls")
        build_mbedtls $2 ;;
    ("json-c")
        build_json_c $2 ;;
    ("c-ares")
        build_c_ares $2 ;;
    *) 
echo "Unknown option
Usage: "$0" <target> [clean]
Supported <target> values:
  all
  jansson
  cjose
  mbedtls
  json-c
  c-ares"
esac
