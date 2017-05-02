
cmake_minimum_required(VERSION 3.6)
project(libxl4bus)

set(CMAKE_C_STANDARD 11)

set(PORT $ENV{LIBXL4BUS_PORT})

function(SET_EMPTY OUTPUT VAL)
    if ((NOT DEFINED ${OUTPUT}) OR "${OUTPUT}" STREQUAL "")
        set(${OUTPUT} "${VAL}" PARENT_SCOPE)
    endif()
endfunction(SET_EMPTY)

if ("${PORT}" STREQUAL "")
    set(PORT "linux_port")
endif()

get_filename_component(PORT "${PORT}" REALPATH BASE_DIR "${CMAKE_SOURCE_DIR}")
get_filename_component(ROOT_DIR "" REALPATH BASE_DIR "${CMAKE_SOURCE_DIR}")

if((NOT IS_DIRECTORY "${PORT}") OR ("${PORT}" STREQUAL "${ROOT_DIR}"))
   message(FATAL_ERROR "LIBXL4BUS_PORT environment variable (${PORT}) must be set and point to a valid port directory!")
endif()

set(LOAD_CFG ${PORT}/config.mk)
if((NOT EXISTS ${LOAD_CFG}) OR (IS_DIRECTORY ${LOAD_CFG}))
    set(LOAD_CFG ${PORT}/config.mk.default)
    if ((NOT EXISTS ${LOAD_CFG}) OR (IS_DIRECTORY ${LOAD_CFG}))
        message(FATAL_ERROR "${PORT} must contain config.mk or config.mk.default file")
    endif()
endif()

include(${LOAD_CFG})

set_empty(BUILD_SHARED TRUE)
set_empty(BUILD_STATIC TRUE)

set(LIB_SOURCE ${LIB_SOURCE}
    src/identity.c
    src/include/libxl4bus/xl4bus.h
    )

if (BUILD_SHARED)
    add_library(xl4bus-shared SHARED ${LIB_SOURCE})
    SET_TARGET_PROPERTIES(xl4bus-shared PROPERTIES OUTPUT_NAME xl4bus CLEAN_DIRECT_OUTPUT 1)
endif()
if (BUILD_STATIC)
    add_library(xl4bus-static STATIC ${LIB_SOURCE})
    SET_TARGET_PROPERTIES(xl4bus-static PROPERTIES OUTPUT_NAME xl4bus CLEAN_DIRECT_OUTPUT 1)
endif()
