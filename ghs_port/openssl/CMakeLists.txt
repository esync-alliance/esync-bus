cmake_minimum_required(VERSION 3.10)

set(CMAKE_SYSTEM_NAME INTEGRITY)

set(LOAD_CFG ${CMAKE_SOURCE_DIR}/config.cmk.openssl)
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

if ("${LIB_OPENSSL_DIR}" STREQUAL "")
  set(LIB_OPENSSL_DIR "${CMAKE_SOURCE_DIR}/openssl")
  if (NOT EXISTS ${LIB_OPENSSL_DIR})
    message(FATAL_ERROR "The openssl dir is not found, please set the LIB_OPENSSL_DIR in the config.cmk.default")
  endif()
endif()

#Install all headers files for reference of other modules
macro(install_headers srcDir dstDir)
  message(STATUS "Installing header files of openssl")
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

macro(apply_patch srcDir dstDir)
  if (NOT EXISTS ${dstDir}/crypto/rand/rand_ghs.c)
    execute_process(COMMAND ${CMAKE_COMMAND} -E create_symlink ${srcDir}/rand_ghs.c ${dstDir}/crypto/rand/rand_ghs.c)
  endif()
  execute_process(COMMAND ln -sf ${srcDir}/bio_pk7.c ${dstDir}/crypto/pkcs7/bio_pk7.c)
endmacro(apply_patch)

configure_files(${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR})
set(OPENSSL_INCLUDE_DIR ${LIB_OPENSSL_DIR}/include/openssl)

if (EXISTS ${OPENSSL_INCLUDE_DIR})
  execute_process(COMMAND rm -rf ${OPENSSL_INCLUDE_DIR})
endif()
make_directory(${OPENSSL_INCLUDE_DIR})

# Generate headers files for compilation
configure_file(${CMAKE_SOURCE_DIR}/opensslconf.h.in ${LIB_OPENSSL_DIR}/crypto/opensslconf.h)
configure_file(${CMAKE_SOURCE_DIR}/buildinf.h.in ${LIB_OPENSSL_DIR}/crypto/buildinf.h)
install_headers(${LIB_OPENSSL_DIR} ${OPENSSL_INCLUDE_DIR})
apply_patch(${CMAKE_SOURCE_DIR} ${LIB_OPENSSL_DIR})

add_custom_target(build_cryto_ssl ALL
  COMMAND ${BUILD_TOOL} -top default.gpj libcrypto.gpj libssl.gpj
  )
