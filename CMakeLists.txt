
cmake_minimum_required(VERSION 3.6)
project(libxl4bus)

set(CMAKE_C_STANDARD 11)
set(CMAKE_VERBOSE_MAKEFILE on)
set(CMAKE_C_VISIBILITY_PRESET hidden)

set(PORT $ENV{LIBXL4BUS_PORT})

# thanks to http://stackoverflow.com/questions/7172670
function(join OUTPUT GLUE)
    set(_TMP_RESULT "")
    set(_GLUE "") # effective glue is empty at the beginning
    foreach(arg ${ARGN})
        set(_TMP_RESULT "${_TMP_RESULT}${_GLUE}${arg}")
        set(_GLUE "${GLUE}")
    endforeach()
    set(${OUTPUT} "${_TMP_RESULT}" PARENT_SCOPE)
endfunction(join)

function(append_env NAME VAL)
    set(TMP $ENV{${NAME}})
    set(ENV{${NAME}} "${TMP} ${VAL}")
endfunction(append_env)

function(set_empty OUTPUT VAL)
    if ((NOT DEFINED ${OUTPUT}) OR "${OUTPUT}" STREQUAL "")
        set(${OUTPUT} "${VAL}" PARENT_SCOPE)
    endif()
endfunction(set_empty)

function(influence_pkg_spec TGT PREFIX)

    if (TARGET ${TGT})
        join(TMP " " ${${PREFIX}_CFLAGS})
        target_compile_options(${TGT} PUBLIC ${TMP})
        join(TMP " " ${${PREFIX}_CFLAGS_OTHER})
        target_compile_options(${TGT} PUBLIC ${TMP})
        join(TMP " " ${${PREFIX}_LDFLAGS})
        set_property(TARGET ${TGT} APPEND_STRING PROPERTY LINK_FLAGS " ${TMP} ")
        join(TMP " " ${${PREFIX}_LDFLAGS_OTHER})
        set_property(TARGET ${TGT} APPEND_STRING PROPERTY LINK_FLAGS " ${TMP} ")
    endif()

endfunction(influence_pkg_spec)

function(influence_pkg PREFIX)
    if (${PREFIX}_FOUND)
        influence_pkg_spec(xl4bus-shared ${PREFIX})
        influence_pkg_spec(xl4bus-static ${PREFIX}_STATIC)
    endif()
endfunction(influence_pkg)

if ("${PORT}" STREQUAL "")
    set(PORT "linux_port")
endif()

get_filename_component(PORT "${PORT}" REALPATH BASE_DIR "${CMAKE_SOURCE_DIR}")
get_filename_component(ROOT_DIR "" REALPATH BASE_DIR "${CMAKE_SOURCE_DIR}")

if((NOT IS_DIRECTORY "${PORT}") OR ("${PORT}" STREQUAL "${ROOT_DIR}"))
   message(FATAL_ERROR "LIBXL4BUS_PORT environment variable (${PORT}) must be set and point to a valid port directory!")
endif()

set(LOAD_CFG ${PORT}/config.cmk)
if((NOT EXISTS ${LOAD_CFG}) OR (IS_DIRECTORY ${LOAD_CFG}))
    set(LOAD_CFG ${PORT}/config.cmk.default)
    if ((NOT EXISTS ${LOAD_CFG}) OR (IS_DIRECTORY ${LOAD_CFG}))
        message(FATAL_ERROR "${PORT} must contain config.cmk or config.cmk.default file")
    endif()
endif()

include(${LOAD_CFG})

set(LOAD_CFG ${PORT}/config.cmk)
if((NOT EXISTS ${LOAD_CFG}) OR (IS_DIRECTORY ${LOAD_CFG}))
    set(LOAD_CFG ${PORT}/config.cmk.default)
    if ((NOT EXISTS ${LOAD_CFG}) OR (IS_DIRECTORY ${LOAD_CFG}))
        message(FATAL_ERROR "${PORT} must contain config.cmk or config.cmk.default file")
    endif()
endif()

include(${LOAD_CFG})

set(LOAD_CFG ${PORT}/config.h)
if((NOT EXISTS ${LOAD_CFG}) OR (IS_DIRECTORY ${LOAD_CFG}))
    set(LOAD_CFG ${PORT}/config.h.default)
    if ((NOT EXISTS ${LOAD_CFG}) OR (IS_DIRECTORY ${LOAD_CFG}))
        message(FATAL_ERROR "${PORT} must contain config.h or config.h.default file")
    endif()
    # can't use COPY because it only copies to dirs.
    # file(COPY ${PORT}/config.h.default ${PORT}/config.h)
    # so the input file better not have any makefile macros.
    file(GENERATE OUTPUT ${PORT}/config.h INPUT ${PORT}/config.h.default)
endif()


set(LOAD_CFG ${PORT}/run.cmk)
if((NOT EXISTS ${LOAD_CFG}) OR (IS_DIRECTORY ${LOAD_CFG}))
    set(LOAD_CFG ${PORT}/run.cmk.default)
    if ((NOT EXISTS ${LOAD_CFG}) OR (IS_DIRECTORY ${LOAD_CFG}))
        message(FATAL_ERROR "${PORT} must contain run.cmk or run.cmk.default file")
    endif()
endif()

set_empty(BUILD_SHARED TRUE)
set_empty(BUILD_STATIC TRUE)

include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/src/include)
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${PORT})

set(LIB_SOURCE ${LIB_SOURCE}
    src/identity.c
    src/misc.c
    src/net.c
    src/internal.h
    src/porting.h
    src/include/libxl4bus/low_level.h
    src/include/libxl4bus/types.h
)

if (BUILD_SHARED)
    add_library(xl4bus-shared SHARED ${LIB_SOURCE})
    SET_TARGET_PROPERTIES(xl4bus-shared PROPERTIES OUTPUT_NAME xl4bus CLEAN_DIRECT_OUTPUT 1)
endif()

if (BUILD_STATIC)
    add_library(xl4bus-static STATIC ${LIB_SOURCE})
    SET_TARGET_PROPERTIES(xl4bus-static PROPERTIES OUTPUT_NAME xl4bus CLEAN_DIRECT_OUTPUT 1)
endif()

include(${LOAD_CFG})
