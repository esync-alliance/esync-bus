cmake_minimum_required(VERSION 3.10)

set(CMAKE_SYSTEM_NAME INTEGRITY)

set(LOAD_CFG ${CMAKE_SOURCE_DIR}/config.cmk)
if (NOT EXISTS ${LOAD_CFG})
  set(LOAD_CFG ${CMAKE_SOURCE_DIR}/../config.cmk.default)
  if (NOT EXISTS ${LOAD_CFG})
    message(FATAL_ERROR "There is no ${LOAD_CFG} file")
  endif()
endif()
include(${LOAD_CFG})

if("${GHS_OS_DIR}" STREQUAL "")
  message(FATAL_ERROR "The GHS_OS_DIR is not found, please set GHS_OS in the config.cmk.default first!")
endif()

if("${GHS_BSP_NAME}" STREQUAL "")
  message(FATAL_ERROR "The GHS_BSP_NAME is not found, please set the GHS_BSP_NAME in the config.cmk.default first")
endif()

if("${BUILD_TOOL_DIR}" STREQUAL "")
  message(FATAL_ERROR "The BUILD_TOOL is not found, please set the BUILD_TOOL in the config.cmk.default  first!")
endif()
set(BUILD_TOOL ${BUILD_TOOL_DIR}/gbuild)

if ("${LIB_JANSSON_DIR}" STREQUAL "")
  set(LIB_JANSSON_DIR "${CMAKE_SOURCE_DIR}/../../jansson")
  if (NOT EXISTS ${LIB_JANSSON_DIR})
    message(FATAL_ERROR "You must set the path of jansson in  config.cmk.default")
  endif()
endif()

if ("${LIB_JANSSON_BUILD_DIR}" STREQUAL "")
  set(LIB_JANSSON_BUILD_DIR "${CMAKE_SOURCE_DIR}/../jansson/build")
  if (NOT EXISTS ${LIB_JANSSON_BUILD_DIR})
    message(FATAL_ERROR "You must build libjansson first")
  endif()
endif()

if ("${LIB_OPENSSL_DIR}" STREQUAL "")
  set(LIB_OPENSSL_DIR "${CMAKE_SOURCE_DIR}/../openssl/openssl")
  if (NOT EXISTS ${LIB_OPENSSL_DIR})
    message(FATAL_ERROR "You must set the path of open ssl build dir in config.cmk.default")
  endif()
endif()

if ("${LIB_CJOSE_DIR}" STREQUAL "")
  set(LIB_CJOSE_DIR "${CMAKE_SOURCE_DIR}/../../cjose")
  if (NOT EXISTS ${LIB_CJOSE_DIR})
    message(FATAL_ERROR "You must set the path of cjose in  config.cmk.default")
  endif()
endif()
execute_process(COMMAND ln -sf ${CMAKE_SOURCE_DIR}/concatkdf.c ${LIB_CJOSE_DIR}/src/concatkdf.c)

set(PACKAGE_VERSION "0.0.6")

#Generate INTEGRITY project files
macro(configure_files srcDir dstDir)
  message(STATUS "Generating the gpj file FROM ${srcDir} TO  directory ${dstDir}")
  file(GLOB cfgFiles RELATIVE ${srcDir} ${srcDir}/*.in)

  foreach(cfgFile in ${cfgFiles})
    set(filePath ${srcDir}/${cfgFile})
    if(EXISTS ${filePath})
      # Remove the extension .in from input file for output file
      string(REGEX REPLACE ".in$" "" dstFile ${cfgFile})
      configure_file(${filePath} ${dstDir}/${dstFile} @ONLY)
    endif()
  endforeach()
endmacro(configure_files)

configure_files(${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR})
configure_file(${LIB_CJOSE_DIR}/include/cjose/version.h.in ${LIB_CJOSE_DIR}/include/cjose/version.h @ONLY)
macro(install_headers srcDir dstDir)
  message(STATUS "Installing header files of cjose")
  file(GLOB_RECURSE headerFiles RELATIVE ${srcDir} ${srcDir}/*.h)
  foreach(headerFile in ${headerFiles})
    set(file ${srcDir}/${headerFile})
    if (EXISTS ${file})
      get_filename_component(name ${headerFile} NAME)
      #message(STATUS "${name}")
      execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${file} ${dstDir}/${name})
    endif()
  endforeach()
endmacro(install_headers)

set(LIB_CJOSE_INCLUDE_DIR "${CMAKE_BINARY_DIR}/include/cjose")
if (NOT EXISTS ${LIB_CJOSE_INCLUDE_DIR})
   make_directory(${LIB_CJOSE_INCLUDE_DIR})
endif()
install_headers(${LIB_CJOSE_DIR} ${LIB_CJOSE_INCLUDE_DIR})

add_custom_target(build_cjose ALL
  COMMAND ${BUILD_TOOL} -top default.gpj libcjose.gpj
  )
