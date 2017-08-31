
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

function(exists_all OUTPUT)
    set(_TMP_RESULT "YES")
    foreach(arg ${ARGN})
        if (NOT EXISTS ${arg})
            set(_TMP_RESULT "NO")
            break()
        endif()
    endforeach()
    set(${OUTPUT} "${_TMP_RESULT}" PARENT_SCOPE)
endfunction(exists_all)

function(append_env NAME VAL)
    set(TMP $ENV{${NAME}})
    set(ENV{${NAME}} "${TMP} ${VAL}")
endfunction(append_env)

function(set_empty OUTPUT VAL)
    if ((NOT DEFINED ${OUTPUT}) OR "${${OUTPUT}}" STREQUAL "")
        set(${OUTPUT} "${VAL}" PARENT_SCOPE)
    endif()
endfunction(set_empty)

function(targets_link_libraries)
    set(LIB_MODE "zz")
    foreach(arg ${ARGN})
        if (${LIB_MODE} STREQUAL TRUE)
            foreach(arg2 ${ARGN})
                message("Applying ${arg2} to target ${arg}")
                if ("${arg2}" STREQUAL "LIBRARIES")
                    break()
                endif()
                if (TARGET ${arg2})
                    target_link_libraries(${arg2} ${arg})
                endif()
            endforeach()
        elseif("${arg}" STREQUAL "LIBRARIES")
            message("Switching to targeting")
            set(LIB_MODE TRUE)
        else()
            message("Delaying target ${arg}")
        endif()
    endforeach()
    message("end targets_link_libraries")
endfunction(targets_link_libraries)

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
    # can't use GENERATE because it creates a make target, and we need it now
    # file(GENERATE OUTPUT ${PORT}/config.h INPUT ${PORT}/config.h.default)
    configure_file(${PORT}/config.h.default ${PORT}/config.h COPYONLY)
endif()

set(LOAD_CFG ${PORT}/types_base.h)
if((NOT EXISTS ${LOAD_CFG}) OR (IS_DIRECTORY ${LOAD_CFG}))
    set(LOAD_CFG ${PORT}/types_base.h.default)
    if ((NOT EXISTS ${LOAD_CFG}) OR (IS_DIRECTORY ${LOAD_CFG}))
        message(FATAL_ERROR "${PORT} must contain types_base.h or types_base.h.default file")
    endif()
    # see comments for above section
    # file(GENERATE OUTPUT ${PORT}/types_base.h INPUT ${PORT}/types_base.h.default)
    configure_file(${PORT}/types_base.h.default ${PORT}/types_base.h COPYONLY)
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
set_empty(WITH_EFENCE FALSE)

set_empty(XL4_PROVIDE_THREADS 1)
set_empty(XL4_PROVIDE_DEBUG 1)
set_empty(XL4_PROVIDE_PRINTF 0)
set_empty(XL4_SUPPORT_IPV6 1)
set_empty(XL4_SUPPORT_IPV4 1)
set_empty(XL4_SUPPORT_THREADS 1)
set_empty(XL4_PROVIDE_GETTIMEOFDAY 1)
set_empty(XL4_SUPPORT_UNIX_DGRAM_PAIR 1)
set_empty(XL4_HAVE_GETTIMEOFDAY 1)
set_empty(XL4_HAVE_STD_MALLOC 1)

set(BCH ${CMAKE_BINARY_DIR}/build_config.h)

configure_file(${CMAKE_SOURCE_DIR}/build_config.h.in ${BCH})
configure_file(${PORT}/types_base.h ${CMAKE_BINARY_DIR}/types_base.h)
configure_file(${CMAKE_SOURCE_DIR}/json-c-rename.h ${CMAKE_BINARY_DIR} COPYONLY)

set(JSON_C ${CMAKE_SOURCE_DIR}/json-c)
set(MBEDTLS ${CMAKE_SOURCE_DIR}/mbedtls)
set(CJOSE ${CMAKE_SOURCE_DIR}/cjose)

include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/src/include)
include_directories(SYSTEM ${JSON_C})
include_directories(SYSTEM ${MBEDTLS}/include)
include_directories(SYSTEM ${CJOSE}/include)
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${PORT})
include_directories(${CMAKE_BINARY_DIR})

set(LIB_SOURCE ${LIB_SOURCE}
    ${BCH}
    ${CMAKE_BINARY_DIR}/types_base.h
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
    src/client.c
    src/x509.c
    src/itc.h
    src/include/libxl4bus/low_level.h
    src/include/libxl4bus/high_level.h
    src/include/libxl4bus/types.h
)

set(JSON_C_LIB ${JSON_C}/.libs/libjson-c.a)
if (NOT EXISTS ${JSON_C_LIB})
    message(FATAL_ERROR "You must build json-c sources first!")
endif()
set(MBEDTLS_LIB ${MBEDTLS}/build/library/libmbedx509.a ${MBEDTLS}/build/library/libmbedcrypto.a)
exists_all(TEST ${MBEDTLS_LIB})
if (NOT ${TEST})
    message(FATAL_ERROR "You must build mbedtls sources first!")
endif()
set(CJOSE_LIB ${CJOSE}/lib/libcjose.a)
exists_all(TEST ${CJOSE_LIB})
if (NOT ${TEST})
    message(FATAL_ERROR "You must build cjose sources first!")
endif()

if (XL4_PROVIDE_THREADS)
    set(THREADS_PREFER_PTHREAD_FLAG TRUE)
    find_package(Threads MODULE REQUIRED)
endif()

if (BUILD_SHARED)
    add_library(xl4bus-shared SHARED ${LIB_SOURCE})
    set_target_properties(xl4bus-shared PROPERTIES OUTPUT_NAME xl4bus CLEAN_DIRECT_OUTPUT 1)
    if (XL4_PROVIDE_THREADS)
        target_link_libraries(xl4bus-shared Threads::Threads)
    endif()
    set(USE_LIB xl4bus-shared)
    target_link_libraries(xl4bus-shared ${JSON_C_LIB} ${MBEDTLS_LIB} ${CJOSE_LIB})
    install(TARGETS xl4bus-shared LIBRARY DESTINATION lib)
endif()

if (BUILD_STATIC)
    file(GLOB EXT_OBJ ${JSON_C}/*.o ${MBEDTLS}/build/library/CMakeFiles/mbedx509.dir/*.o ${MBEDTLS}/build/library/CMakeFiles/mbedcrypto.dir/*.o ${CJOSE}/src/*.o)
    add_library(xl4bus-static STATIC ${LIB_SOURCE} ${EXT_OBJ})
    set_target_properties(xl4bus-static PROPERTIES OUTPUT_NAME xl4bus CLEAN_DIRECT_OUTPUT 1)
    if (XL4_PROVIDE_THREADS)
        target_link_libraries(xl4bus-static Threads::Threads)
    endif()
    if (NOT USE_LIB)
        set(USE_LIB xl4bus-static)
    endif()
    target_compile_definitions(xl4bus-static PUBLIC HIDE_SYM)
    install(TARGETS xl4bus-static ARCHIVE DESTINATION lib)
endif()

if (BUILD_BINS)
    add_executable(ll-server src/test_clients/ll-server.c)
    add_executable(ll-client src/test_clients/ll-client.c)
    add_executable(hl-client
            src/test_clients/hl-client.c
            src/broker/common.h
            src/broker/common.c
            )
    add_executable(xl4bus-broker
            src/broker/main.c
            src/broker/debug.h
            src/uthash.h
            src/utarray.h
            src/broker/common.h
            src/broker/common.c
    )

    install(TARGETS xl4bus-broker RUNTIME DESTINATION bin)

    include(FindPkgConfig)

    pkg_check_modules(JANSSON REQUIRED jansson)
    influence_pkg("JANSSON")

    # influence_pkg_spec(ll-server JANSSON)
    # influence_pkg_spec(ll-client JANSSON)

    target_link_libraries(xl4bus-broker ${JSON_C_LIB})

    if (WITH_EFENCE)
        targets_link_libraries("ll-server" "ll-client" "hl-client" "xl4bus-broker" LIBRARIES -lefence)
    endif()

    targets_link_libraries("ll-server" "ll-client" "hl-client" "xl4bus-broker" LIBRARIES ${USE_LIB})

    # target_link_libraries("ll-server" ${USE_LIB})
    # target_link_libraries("ll-client" ${USE_LIB})
    # target_link_libraries("hl-client" ${USE_LIB})
    # target_link_libraries("xl4bus-broker" ${USE_LIB})
    if (XL4_PROVIDE_THREADS)
        targets_link_libraries(ll-server hl-server LIBRARIES Threads::Threads)
        # target_link_libraries(ll-server Threads::Threads)
        # target_link_libraries(hl-client Threads::Threads)
    else()
        message(FATAL_ERROR "Binaries require threading support that is not enabled. You probably want to disable binaries being built as well.")
    endif()
endif()

install(DIRECTORY src/include/libxl4bus DESTINATION include/libxl4bus)
install(FILES ${BCH} DESTINATION include/libxl4bus)
install(FILES ${CMAKE_BINARY_DIR}/types_base.h DESTINATION include/libxl4bus)

find_package(Doxygen)

if (NOT DOXYGEN_FOUND)

    message(WARNING "Doxygen is needed to build the documentation, skipping documentation build now")

else ()

    set(doxyfile_in ${CMAKE_HOME_DIRECTORY}/doc/doxyfile.in)
    set(doxyfile ${CMAKE_CURRENT_BINARY_DIR}/doxyfile)

    configure_file(${doxyfile_in} ${doxyfile} @ONLY)

    add_custom_target(doc ALL
            COMMAND ${DOXYGEN_EXECUTABLE} ${doxyfile}
            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/doc
            SOURCES
                ${doxyfile_in} ${doxyfile}
                ${BCH}
                src/include/libxl4bus/high_level.h
                src/include/libxl4bus/low_level.h
                src/include/libxl4bus/types.h
            VERBATIM)

    install(DIRECTORY ${CMAKE_BINARY_DIR}/html DESTINATION share/doc/libxl4bus)

endif ()

include(${LOAD_CFG})
