#!/bin/bash

CMK=$(type -p cmake)
if test -d ${HOME}/cmake-3.8/bin/cmake; then
    CMK=${HOME}/cmake-3.8/bin/cmake
fi
if test -n "$CMAKE_38"; then
    CMK="$CMAKE_38"
fi

TCR=${HOME}/tmp/arm-23

if test -n "$USE_ANDROID_TOOLCHAIN"; then
    TCR="$USE_ANDROID_TOOLCHAIN"
fi

export SYSROOT="${TCR}/sysroot"

export CROSS_COMPILE=arm-linux-androideabi
export PROJECT_ROOT=`pwd`
export CFLAGS="-I $SYSROOT/usr/include -DANDROID_NDK=1 -I $PROJECT_ROOT/android/include"
export LDFLAGS="-L $SYSROOT/usr/lib -lm -lz -L $PROJECT_ROOT/android/lib "

export PKG_CONFIG_PATH="${SYSROOT}/lib/pkgconfig:${SYSROOT}/usr/lib/pkgconfig"

export CC="$TCR/bin/arm-linux-androideabi-gcc --sysroot=$SYSROOT"

rm -rf android_build
mkdir -p android_build

(cd android_build && {
    ${CMK} -DCMAKE_BUILD_TYPE=Debug -DCMAKE_ANDROID_ARM_MODE=ON -DCMAKE_SYSTEM_NAME=Android -DCMAKE_ANDROID_STANDALONE_TOOLCHAIN=${TCR} ..
    make
}
)
