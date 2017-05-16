
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
        target_compile_options(${TGT} PUBLIC ${${PREFIX}_CFLAGS})
        target_compile_options(${TGT} PUBLIC ${${PREFIX}_CFLAGS_OTHER})

        target_link_libraries(${TGT} ${${PREFIX}_LDFLAGS})
        target_link_libraries(${TGT} ${${PREFIX}_LDFLAGS_OTHER})
    endif()

endfunction(influence_pkg_spec)

function(influence_pkg PREFIX)
    if (${PREFIX}_FOUND)
        influence_pkg_spec(xl4bus-shared ${PREFIX})
        influence_pkg_spec(xl4bus-static ${PREFIX}_STATIC)
        influence_pkg_spec(ll-server ${PREFIX})
        influence_pkg_spec(ll-client ${PREFIX})
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

set(LOAD_CFG ${PORT}/types_base.h)
if((NOT EXISTS ${LOAD_CFG}) OR (IS_DIRECTORY ${LOAD_CFG}))
    set(LOAD_CFG ${PORT}/types_base.h.default)
    if ((NOT EXISTS ${LOAD_CFG}) OR (IS_DIRECTORY ${LOAD_CFG}))
        message(FATAL_ERROR "${PORT} must contain types_base.h or types_base.h.default file")
    endif()
    # can't use COPY because it only copies to dirs.
    # file(COPY ${PORT}/config.h.default ${PORT}/config.h)
    # so the input file better not have any makefile macros.
    file(GENERATE OUTPUT ${PORT}/types_base.h INPUT ${PORT}/types_base.h.default)
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
set_empty(BUILD_BINS TRUE)
set_empty(USE_THREADS TRUE)
set_empty(LIB_DEBUG TRUE)

include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/src/include)
include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/json-c)
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${PORT})

set(LIB_SOURCE ${LIB_SOURCE}
    src/identity.c
    src/misc.c
    src/net.c
    src/signed.c
    src/internal.h
    src/porting.h
    src/misc.h
    src/uthash.h
    src/utlist.h
    src/debug.h
    src/printf.h
    src/printf.c
    src/include/libxl4bus/low_level.h
    src/include/libxl4bus/types.h
)

set(JSON_C_LIB ${CMAKE_SOURCE_DIR}/json-c/.libs/libjson-c.a)
if (NOT EXISTS ${JSON_C_LIB})
    message(FATAL_ERROR You must build json-c sources first!)
endif()

if (USE_THREADS)
    set(THREADS_PREFER_PTHREAD_FLAG TRUE)
    find_package(Threads MODULE REQUIRED)
endif()

if (BUILD_SHARED)
    add_library(xl4bus-shared SHARED ${LIB_SOURCE})
    set_target_properties(xl4bus-shared PROPERTIES OUTPUT_NAME xl4bus CLEAN_DIRECT_OUTPUT 1)
    if (USE_THREADS)
        target_link_libraries(xl4bus-shared Threads::Threads)
    endif()
    set(USE_LIB xl4bus-shared)
    target_link_libraries(xl4bus-shared ${JSON_C_LIB})
endif()

if (BUILD_STATIC)
    add_library(xl4bus-static STATIC ${LIB_SOURCE})
    set_target_properties(xl4bus-static PROPERTIES OUTPUT_NAME xl4bus CLEAN_DIRECT_OUTPUT 1)
    if (USE_THREADS)
        target_link_libraries(xl4bus-static Threads::Threads)
    endif()
    if (NOT USE_LIB)
        set(USE_LIB xl4bus-static)
    endif()
    target_link_libraries(xl4bus-static ${JSON_C_LIB})
endif()

if (BUILD_BINS)
    add_executable(ll-server src/ll-server.c)
    add_executable(ll-client src/ll-client.c)

    include(FindPkgConfig)

    pkg_check_modules(JANSSON REQUIRED jansson)
    influence_pkg("JANSSON")

    influence_pkg_spec(ll-server JANSSON)
    influence_pkg_spec(ll-client JANSSON)

    target_link_libraries("ll-server" ${USE_LIB})
    target_link_libraries("ll-client" ${USE_LIB})
    if (USE_THREADS)
        target_link_libraries(ll-server Threads::Threads)
    else()
        message(FATAL_ERROR "Binaries require threading support that is not enabled. You probably want to disable binaries being built as well.")
    endif()
endif()

include(${LOAD_CFG})
