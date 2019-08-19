#!/bin/sh

portdir=`pwd`
rootdir=${portdir}/..

build_jansson () {

	cd ${rootdir}
	
	if [ ! -d jansson-build ];then
		cp -rf jansson jansson-build
	fi
	
	cd jansson-build

	if [ ! -d build ];then
		cp -rf ${portdir}/jansson build
		cp ${portdir}/qnx.cmake build
		cd build
		cmake -DCMAKE_TOOLCHAIN_FILE=qnx.cmake -DJANSSON_BUILD_SHARED_LIBS=ON || return 1
		make || return 1
	fi

	return 0
}

build_cjose () {

	cd ${rootdir}
	
	if [ ! -d cjose-build ];then
		cp -rf cjose cjose-build
		cd cjose-build
		cp ${portdir}/cjose/qnx.patch .
		patch -p0 < qnx.patch
		cd ..
	fi
	
	cd cjose-build

	if [ ! -e lib/libcjose.a ];then
		export WITH_JANSSON=${rootdir}/jansson-build/build
		autoreconf -f -i || return 1
		./configure --host=arm-unknown-nto-qnx7.0.0eabi --with-openssl=${QNX_TARGET} -with-jansson=${WITH_JANSSON} --enable-static --disable-shared || return 1
		make CFLAGS='-fPIC -fvisibility=hidden' || return 1
	fi

	return 0
}

build_mbedtls () {

	cd ${rootdir}
	
	if [ ! -d mbedtls-build ];then
		cp -rf mbedtls mbedtls-build
		cd mbedtls-build
		./scripts/config.pl set MBEDTLS_PLATFORM_MEMORY
		cd ..
	fi
	
	cd  mbedtls-build

	if [ ! -d build ];then
		mkdir build
		cp ${portdir}/qnx.cmake build
		cd build
		cmake -DCMAKE_TOOLCHAIN_FILE=qnx.cmake -DCMAKE_C_FLAGS="-fPIC -fvisibility=hidden" -DENABLE_PROGRAMS=OFF -DENABLE_TESTING=OFF .. || return 1
		make || return 1
	fi

	return 0
}

build_json_c () {

	cd ${rootdir}
	
	if [ ! -d json-c-build ];then
		cp -rf json-c json-c-build
	fi
	
	cd json-c-build

	if [ ! -e .libs/libjson-c.a ]; then
		autoreconf -f -i || return 1
		./configure --host=arm-unknown-nto-qnx7.0.0eabi ac_cv_func_malloc_0_nonnull=yes ac_cv_func_realloc_0_nonnull=yes --enable-static --disable-shared || return 1
		make CFLAGS='-fPIC -fvisibility=hidden -Wno-implicit-fallthrough' CPPFLAGS='-include $(PWD)/../json-c-rename.h' || return 1
	fi
}

if [ "$1" = 'clean' ] ; then
	rm -rf ${rootdir}/cjose-build
	rm -rf ${rootdir}/json-c-build
	rm -rf ${rootdir}/jansson-build
	rm -rf ${rootdir}/mbedtls-build
	exit 0
else
	build_jansson
	if [ $? -eq 1 ]; then
		rm -rf ${rootdir}/jansson-build/build
		exit 1
	fi
	build_cjose
	if [ $? -eq 1 ]; then
		exit 1
	fi
	build_mbedtls
	if [ $? -eq 1 ]; then
		rm -rf ${rootdir}/mbedtls-build/build
		exit 1
	fi
	build_json_c
	if [ $? -eq 1 ]; then
		exit 1
	fi
fi

echo "Done!"

exit 0


