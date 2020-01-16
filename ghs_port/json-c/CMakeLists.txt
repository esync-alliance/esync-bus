cmake_minimum_required(VERSION 3.10)
project(json-c)

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

if ("${LIB_JSONC_DIR}" STREQUAL "")
  set(LIB_JSONC_DIR "${CMAKE_SOURCE_DIR}/../../json-c")
  if (NOT EXISTS ${LIB_JSONC_DIR})
    message(FATAL_ERROR "You must set the path of jsonc in the config.cmk or config.cmk.default")
  endif()
endif()

if ("${LIB_GHS_MISC_DIR}" STREQUAL "")
  set(LIB_GHS_MISC_DIR "${CMAKE_SOURCE_DIR}/../ghs_misc")
  if (NOT EXISTS ${LIB_GHS_MISC_DIR})
    message(FATAL_ERROR "You must set the path of ghs_misc which provied unsupported linux-like apis")
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
      string(REGEX REPLACE ".in$" "" dstFile ${cfgFile})
      configure_file(${filePath} ${dstDir}/${dstFile} @ONLY)
    endif()
  endforeach()
endmacro(configure_files)

configure_files(${CMAKE_SOURCE_DIR} ${CMAKE_BINARY_DIR})

add_custom_target(build_jsonc ALL
  COMMAND ${BUILD_TOOL} -top default.gpj libjsonc.gpj
  )
