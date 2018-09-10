#!/bin/bash -e
git submodule init
git submodule update

#DBG="-g -O0"

# Build json-c:
rm -rf json-c-build
cp -fr json-c json-c-build
pushd json-c-build
autoreconf -f -i
CFLAGS="-fPIC -fvisibility=hidden -Wno-implicit-fallthrough" \
CPPFLAGS="-include $(pwd)/../json-c-rename.h" \
./configure --enable-static --disable-shared
make -j
popd

# Build mbedtls:
rm -rf mbedtls-build
cp -fr mbedtls mbedtls-build
pushd mbedtls-build
./scripts/config.pl set MBEDTLS_PLATFORM_MEMORY
mkdir -p build
cd build
cmake -DCMAKE_C_FLAGS="$DBG -fPIC -fvisibility=hidden" ..
make -j
popd

#Build cjose:
rm -rf cjose-build
cp -fr cjose cjose-build
pushd cjose-build
autoreconf -f -i
CFLAGS="$DBG -fPIC -fvisibility=hidden" \
./configure --with-openssl=/usr --with-jansson=/usr --enable-static --disable-shared
make -j
popd

#Build c-ares:
rm -rf c-ares-build
cp -fr c-ares c-ares-build
pushd c-ares-build
./buildconf
CFLAGS="$DBG -fPIC -fvisibility=hidden" \
./configure --enable-static --disable-shared
make -j
popd

rm -rf Release
mkdir Release
cd Release
cmake -DCMAKE_BUILD_TYPE=Release ..
make -j
