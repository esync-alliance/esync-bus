#!/bin/sh

set -e

portdir=`pwd`

rm -rf ${portdir}/../jansson-build
rm -rf ${portdir}/../cjose-build
rm -rf ${portdir}/../mbedtls-build
rm -rf ${portdir}/../json-c-build
rm -rf ${portdir}/build
rm -rf ${portdir}/*.h

if [ "$1" = 'clean' ] ; then
	rm -rf ${portdir}/../jansson
	exit 0
fi

cd ${portdir}/../

if [ ! -d jansson ];then
	git clone https://github.com/akheron/jansson.git
	cd jansson
	git checkout tags/v2.10
fi

cd ${portdir}/../

cp -rf jansson jansson-build
cp -rf qnx_port/jansson jansson-build/qnx
cd jansson-build/qnx
mkdir build
cd build
cmake -DCMAKE_TOOLCHAIN_FILE=qnx.cmake -DJANSSON_BUILD_SHARED_LIBS=ON ..
make

cd ${portdir}/../

cp -rf cjose cjose-build
cp qnx_port/cjose/qnx.patch cjose-build
cd cjose-build
patch -p0 < qnx.patch
export WITH_JANSSON=`pwd`/../jansson-build/qnx/build
./configure --host=arm-unknown-nto-qnx7.0.0eabi --with-openssl=${QNX_TARGET} -with-jansson=${WITH_JANSSON} --enable-static --disable-shared
make CFLAGS='-fPIC -fvisibility=hidden'

cd ${portdir}/../

cp -rf mbedtls mbedtls-build
cp -rf qnx_port/mbedtls mbedtls-build/qnx
cd mbedtls-build
./scripts/config.pl set MBEDTLS_PLATFORM_MEMORY
cd qnx
mkdir build
cd build
cmake -DCMAKE_TOOLCHAIN_FILE=qnx.cmake -DCMAKE_C_FLAGS="-fPIC -fvisibility=hidden" -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON ..
make

cd ${portdir}/../

cp -rf json-c json-c-build
cd json-c-build
autoreconf -f -i
./configure --host=arm-unknown-nto-qnx7.0.0eabi ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes --enable-static --disable-shared
make CFLAGS='-fPIC -fvisibility=hidden -Wno-implicit-fallthrough' CPPFLAGS='-include $(PWD)/../json-c-rename.h'

cd ${portdir}

export LIBXL4BUS_PORT=.
mkdir build
cd build
cmake -DCMAKE_TOOLCHAIN_FILE=qnx.cmake -DBUILD_SHARED=ON -DBUILD_STATIC=OFF -DXL4_SUPPORT_IPV6=0 ..
make