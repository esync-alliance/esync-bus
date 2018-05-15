#!/bin/sh

portdir=`pwd`
rootdir=${portdir}/..
buildir=${rootdir}/build_qnx

build_lib () {

	cd ${rootdir}

	export LIBXL4BUS_PORT=qnx_port
	
	cd ${buildir}
	
	cmake -DCMAKE_TOOLCHAIN_FILE=../qnx_port/qnx.cmake -DBUILD_STATIC=OFF -DXL4_SUPPORT_IPV6=0 -DXL4_HAVE_EPOLL=0 .. || return 1
	make || return 1

	return 0
}

if [ "$1" = 'clean' ] ; then
	rm -rf ${buildir}
	rm -f ${portdir}/*.h
	exit 0
else
	if [ ! -d ${buildir} ];then
		mkdir -p ${buildir}
	fi
	build_lib
	if [ $? -eq 1 ]; then
		rm -rf ${buildir}
		rm -f ${portdir}/*.h
		exit 1
	fi
fi

echo "Done!"

exit 0



