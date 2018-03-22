#!/bin/sh

portdir=`pwd`

build_lib () {

	cd ${portdir}/../

	export LIBXL4BUS_PORT=qnx_port

	if [ ! -d build ];then
		mkdir build
		cd build
		cmake -DCMAKE_TOOLCHAIN_FILE=../qnx_port/qnx.cmake -DBUILD_SHARED=ON -DBUILD_STATIC=OFF -DXL4_SUPPORT_IPV6=0 .. || return 1
		make || return 1
	fi

	return 0
}

if [ "$1" = 'clean' ] ; then
	rm -rf ${portdir}/../build
	rm -f ${portdir}/*.h
	exit 0
else
	build_lib
	if [ $? -eq 1 ]; then
		rm -rf ${portdir}/../build
		rm -f ${portdir}/*.h
		exit 1
	fi
fi

echo "Done!"

exit 0



