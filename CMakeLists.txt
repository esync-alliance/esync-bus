
cmake_minimum_required(VERSION 3.5)
project(libxl4bus)

set(CMAKE_C_STANDARD 11)
set(CMAKE_VERBOSE_MAKEFILE on)
set(CMAKE_C_VISIBILITY_PRESET hidden)
#set(CMAKE_BUILD_TYPE Debug)

set(PORT $ENV{LIBXL4BUS_PORT})

add_custom_command(OUTPUT PHONY ${CMAKE_BINARY_DIR}/xl4bus_version.h COMMAND ${CMAKE_SOURCE_DIR}/make_version.sh ARGS ${CMAKE_SOURCE_DIR} WORKING_DIRECTORY ${CMAKE_BINARY_DIR})

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
set_empty(XL4_HAVE_EPOLL 1)

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES build_config.h)

set(BUILD_INCLUDE ${CMAKE_BINARY_DIR}/include)
set(BUILD_INCLUDE_BUS ${BUILD_INCLUDE}/libxl4bus)
file(MAKE_DIRECTORY ${BUILD_INCLUDE_BUS})

set(BCH ${BUILD_INCLUDE_BUS}/build_config.h)

configure_file(${CMAKE_SOURCE_DIR}/build_config.h.in ${BCH})
configure_file(${PORT}/types_base.h ${BUILD_INCLUDE_BUS}/types_base.h)
configure_file(${CMAKE_SOURCE_DIR}/json-c-rename.h ${CMAKE_BINARY_DIR} COPYONLY)

include_directories(SYSTEM ${CMAKE_SOURCE_DIR}/src/include)
include_directories(SYSTEM ${BUILD_INCLUDE})
include_directories(${CMAKE_SOURCE_DIR}/src)
include_directories(${PORT})
include_directories(${CMAKE_BINARY_DIR})

set(JSON_C ${CMAKE_SOURCE_DIR}/json-c-build)
set(MBEDTLS ${CMAKE_SOURCE_DIR}/mbedtls-build)
set(CJOSE ${CMAKE_SOURCE_DIR}/cjose-build)
set(CARES ${CMAKE_SOURCE_DIR}/c-ares-build)
set(JANSSON ${CMAKE_SOURCE_DIR}/jansson-build)

include_directories(SYSTEM ${JSON_C})
include_directories(SYSTEM ${MBEDTLS}/include)
include_directories(SYSTEM ${CJOSE}/include)
include_directories(SYSTEM ${CARES})
include_directories(SYSTEM ${JANSSON}/build/include)

set(LIB_SOURCE ${LIB_SOURCE}
    PHONY
    ${BCH}
    ${BUILD_INCLUDE_BUS}/types_base.h
    ${CMAKE_BINARY_DIR}/xl4bus_version.h
    src/identity.c
    src/misc.c
    src/net.c
        src/jwx.c
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
    src/addr.c
    src/timeout.c
    src/itc.h
    src/include/libxl4bus/low_level.h
    src/include/libxl4bus/high_level.h
    src/include/libxl4bus/types.h
    src/lib/rb_tree.h
    src/lib/rb_tree.c
)

set(DEPS_CFG ${PORT}/deps.cmk)
if((NOT EXISTS ${DEPS_CFG}) OR (IS_DIRECTORY ${DEPS_CFG}))
    set(DEPS_CFG ${PORT}/deps.cmk.default)
    if ((NOT EXISTS ${DEPS_CFG}) OR (IS_DIRECTORY ${DEPS_CFG}))
        message(FATAL_ERROR "${PORT} must contain deps.cmk or deps.cmk.default file")
    endif()
endif()

include(${DEPS_CFG})

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
    target_link_libraries(xl4bus-shared ${SHARED_LIBS})
    target_compile_definitions(xl4bus-shared PUBLIC XL4BUS_BUILD)
    install(TARGETS xl4bus-shared LIBRARY DESTINATION lib)
endif()

if (BUILD_STATIC)
    add_library(xl4bus-static STATIC ${LIB_SOURCE} ${EXT_OBJ})
    set_target_properties(xl4bus-static PROPERTIES OUTPUT_NAME xl4bus CLEAN_DIRECT_OUTPUT 1)
    # Still make PIC code, for possible inclusion into shared libs, e.g. DMClient
    # Specifically needed for MLX2018-64
    set_target_properties(xl4bus-static PROPERTIES POSITION_INDEPENDENT_CODE True)
    if (XL4_PROVIDE_THREADS)
        target_link_libraries(xl4bus-static Threads::Threads)
    endif()
    if (NOT USE_LIB)
        set(USE_LIB xl4bus-static)
    endif()
    target_link_libraries(xl4bus-static ${STATIC_LIBS})
    target_compile_definitions(xl4bus-static PRIVATE HIDE_SYM XL4BUS_BUILD)
    install(TARGETS xl4bus-static ARCHIVE DESTINATION lib)
endif()

if (BUILD_BINS)

    set(LIB_SRC
        src/lib/common.h
        src/lib/common.c
        src/lib/debug.h
        src/lib/debug.c
        src/lib/rb_tree.h
        src/lib/rb_tree.c
        src/lib/poll_help.h
        ${PORT_SOURCE}
    )

    add_executable(ll-client
            src/test_clients/ll-client.c
            ${LIB_SRC}
        )
    add_executable(xl4bus-broker
            src/broker/broker.h
            src/broker/bus.c
            src/broker/crypto.c
            src/broker/e900.c
            src/broker/gather.c
            src/broker/hash_list.h
            src/broker/hash_tree.c
            src/broker/main.c
            src/uthash.h
            src/utarray.h
            ${LIB_SRC}
        )

    add_executable(tree-test
        src/tests/tree.c
        ${LIB_SRC}
        )

    if (XL4_HAVE_EPOLL)
        add_executable(timeout-test
            src/tests/timeout.c
            ${LIB_SRC}
            )
        set(TEST_BINARIES "tree-test" "timeout-test")
    else()
        set(TEST_BINARIES "tree-test")
    endif()

    set(BINARIES "ll-client" "xl4bus-broker" ${TEST_BINARIES})

    if (XL4_PROVIDE_THREADS)

        add_executable(ll-server
                src/test_clients/ll-server.c
                ${LIB_SRC}
            )
        add_executable(hl-client
                src/test_clients/hl-client.c
                ${LIB_SRC}
            )
        targets_link_libraries(ll-server hl-client LIBRARIES Threads::Threads)
        set(BINARIES ${BINARIES} ll-server hl-client)
    else()
        message(WARNING "Some binaries require threading support, those binaries have not been built")
    endif()

    install(TARGETS xl4bus-broker RUNTIME DESTINATION bin)
    
    target_link_libraries(xl4bus-broker ${JSON_C_LIB})
    
    if (WITH_EFENCE)
        targets_link_libraries(${BINARIES} LIBRARIES -lefence)
    endif()

    targets_link_libraries(${BINARIES} LIBRARIES ${USE_LIB})

endif()

install(DIRECTORY src/include/libxl4bus DESTINATION include)
install(FILES ${BCH} DESTINATION include/libxl4bus)
install(FILES ${BUILD_INCLUDE_BUS}/types_base.h ${BUILD_INCLUDE_BUS}/build_config.h DESTINATION include/libxl4bus)

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

if (CMAKE_CROSSCOMPILING)
    message(WARNING "Please remember to run tests on the target platform!")
else()

    if (BUILD_BINS)
        enable_testing()
        add_test(NAME unit-tree COMMAND tree-test)
        add_test(NAME unit-timeout COMMAND timeout-test)
        add_custom_command(
            TARGET xl4bus-broker
            DEPENDS ${TEST_BINARIES}
            COMMENT "Run tests"
            POST_BUILD
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMAND ${CMAKE_CTEST_COMMAND} -C $<CONFIGURATION> -V -R "^unit-"
        )

        add_dependencies(xl4bus-broker ${TEST_BINARIES})

    endif()

endif()

include(${LOAD_CFG})
