cmake_minimum_required(VERSION 3.10)
project(mbedtls)

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

if ("${LIB_MBEDTLS_DIR}" STREQUAL "")
  set(LIB_MBEDTLS_DIR ${CMAKE_SOURCE_DIR}/../../mbedtls)
  if (NOT EXISTS ${LIB_MBEDTLS_DIR})
    message(FATAL_ERROR "You must set the path of mbedtls in the config.cmk or config.cmk.default")
  endif()
endif()

#Generate INTEGRITY project files
macro(configure_files srcDir dstDir)
  message(STATUS "Generating the gpj file FROM ${srcDir} TO  directory ${dstDir}")
  file(GLOB cfgFiles RELATIVE ${srcDir} ${srcDir}/*.in)

  foreach(cfgFile in ${cfgFiles})
    set(filePath ${srcDir}/${cfgFile})
    if(EXISTS ${filePath})
      # Remove the extension .in from input file for output file
      string(REPLACE ".in" "" dstFile ${cfgFile})
      configure_file(${filePath} ${dstDir}/${dstFile} @ONLY)
    endif()
  endforeach()
endmacro(configure_files)
macro(apply_patch srcDir dstDir)
  execute_process(COMMAND ln -sf ${srcDir}/net_sockets.c ${dstDir}/library/net_sockets.c)
  execute_process(COMMAND ln -sf ${srcDir}/timing.c ${dstDir}/library/timing.c)
  execute_process(COMMAND ln -sf ${srcDir}/x509.c ${dstDir}/library/x509.c)
endmacro(apply_patch)

macro(install_headers srcDir dstDir)
  message(STATUS "Installing header files of mbedtls")
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

if (NOT EXISTS ${CMAKE_BINARY_DIR}/include/mbedtls)
  make_directory(${CMAKE_BINARY_DIR}/include/mbedtls)
endif()
install_headers(${LIB_MBEDTLS_DIR} ${CMAKE_BINARY_DIR}/include/mbedtls)

configure_files(${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR})
apply_patch(${CMAKE_SOURCE_DIR}/modified_code ${LIB_MBEDTLS_DIR})

add_custom_target(build_mbedtls ALL
  COMMAND ${BUILD_TOOL} -top default.gpj libmbedtls.gpj
  )
