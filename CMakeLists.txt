
cmake_minimum_required(VERSION 3.5)
project(xl4bus
    DESCRIPTION "Excelfore eSync Bus"
    LANGUAGES "C"
    )

# Set PROJECT_VERSION base on GIT Tag
execute_process(COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/get_projver.sh
    OUTPUT_VARIABLE GIT_DESCRIBE_TAG_VERSION
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

set(PROJECT_VERSION ${GIT_DESCRIBE_TAG_VERSION})
string(REPLACE "." ";" VERSION_LIST ${GIT_DESCRIBE_TAG_VERSION})
list(GET VERSION_LIST 0 PROJECT_VERSION_MAJOR)
list(GET VERSION_LIST 1 PROJECT_VERSION_MINOR)
list(GET VERSION_LIST 2 PROJECT_VERSION_PATCH)
list(GET VERSION_LIST 3 PROJECT_VERSION_TWEAK)

set(CMAKE_C_STANDARD 11)
set(CMAKE_VERBOSE_MAKEFILE on)
set(CMAKE_C_VISIBILITY_PRESET hidden)

set(PORT $ENV{LIBXL4BUS_PORT})

add_custom_command(OUTPUT PHONY ${CMAKE_CURRENT_BINARY_DIR}/xl4bus_version.h
    COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/make_version.sh
    ARGS ${CMAKE_CURRENT_SOURCE_DIR}
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

if (DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 -ggdb")
endif()

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
    else()
        MESSAGE("${TGT}" " is not a target!")
    endif()

endfunction(influence_pkg_spec)

function(influence_pkg PREFIX)
    if (${PREFIX}_FOUND)
        influence_pkg_spec(xl4bus-shared ${PREFIX})
        influence_pkg_spec(xl4bus-static ${PREFIX}_STATIC)
        foreach(arg ${BINARIES})
            influence_pkg_spec("${arg}" ${PREFIX})
        endforeach()
    endif()
endfunction(influence_pkg)

if ("${PORT}" STREQUAL "")
    set(PORT "linux_port")
endif()

get_filename_component(PORT "${PORT}" REALPATH BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
get_filename_component(ROOT_DIR "" REALPATH BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

if((NOT IS_DIRECTORY "${PORT}") OR ("${PORT}" STREQUAL "${ROOT_DIR}"))
   message(FATAL_ERROR "LIBXL4BUS_PORT environment variable (${PORT}) must be set and point to a valid port directory!")
endif()

if(BUILD_DEPENDENCIES)
    if(NOT EXISTS ${PORT}/build_deps.done)
        message(STATUS "Building ${PROJECT_NAME} External Dependendcies...")
        execute_process(COMMAND ./build_deps.sh clean
            OUTPUT_FILE ${CMAKE_CURRENT_BINARY_DIR}/CMakeExtDepsClean.log
            ERROR_FILE ${CMAKE_CURRENT_BINARY_DIR}/CMakeExtDepsClean.log
            WORKING_DIRECTORY "${PORT}")
        execute_process(COMMAND ./build_deps.sh
            OUTPUT_FILE ${CMAKE_CURRENT_BINARY_DIR}/CMakeExtDepsBuild.log
            ERROR_FILE ${CMAKE_CURRENT_BINARY_DIR}/CMakeExtDepsBuild.log
            WORKING_DIRECTORY "${PORT}")
        message(STATUS "${PROJECT_NAME} External Dependencies Build Finished...")
    endif()
endif(BUILD_DEPENDENCIES)

set(RUN_TESTS TRUE)
if (CMAKE_CROSSCOMPILING)
    set(RUN_TESTS FALSE)
elseif(NOT CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(RUN_TESTS FALSE)
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

add_definitions(-DHAVE_JSONC_RENAME)

if(ESYNC_ALLIANCE)
	add_definitions(-DESYNC_ALLIANCE)
endif()

set_empty(BUILD_SHARED TRUE)
set_empty(BUILD_STATIC TRUE)
set_empty(BUILD_BINS TRUE)
set_empty(WITH_EFENCE FALSE)

set_empty(XL4_PROVIDE_THREADS 1)
set_empty(XL4_PROVIDE_DEBUG 1)
set_empty(XL4_PROVIDE_PRINTF 0)
set_empty(XL4_PROVIDE_VASPRINTF 0)
set_empty(XL4_PROVIDE_EPOLL 0)
set_empty(XL4_PROVIDE_PERF 0)
set_empty(XL4_SUPPORT_IPV6 1)
set_empty(XL4_SUPPORT_IPV4 1)
set_empty(XL4_SUPPORT_THREADS 1)
set_empty(XL4_SUPPORT_RESOLVER 1)
set_empty(XL4_SUPPORT_UNIX_DGRAM_PAIR 1)
set_empty(XL4_HAVE_GETTIMEOFDAY 1)
set_empty(XL4_HAVE_STD_MALLOC 1)
set_empty(XL4_SYMBOL_VISIBILITY_SUPPORTED 1)

set_directory_properties(PROPERTIES ADDITIONAL_MAKE_CLEAN_FILES build_config.h)

set(BUILD_INCLUDE ${CMAKE_CURRENT_BINARY_DIR}/include)
set(BUILD_INCLUDE_BUS ${BUILD_INCLUDE}/libxl4bus)
file(MAKE_DIRECTORY ${BUILD_INCLUDE_BUS})

set(BCH ${BUILD_INCLUDE_BUS}/build_config.h)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/build_config.h.in ${BCH})
configure_file(${PORT}/types_base.h ${BUILD_INCLUDE_BUS}/types_base.h)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/json-c-rename.h ${CMAKE_CURRENT_BINARY_DIR} COPYONLY)

include_directories(SYSTEM ${CMAKE_CURRENT_SOURCE_DIR}/src/include)
include_directories(SYSTEM ${BUILD_INCLUDE})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src/tests)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
include_directories(${PORT})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

if(ENABLE_YOCTO_BUILD)
    set(JSON_C ${BITBAKE_STAGING_DIR}/xl4bus/libjson-c)
    set(MBEDTLS ${BITBAKE_STAGING_DIR}/xl4bus/libmbedtls)
    set(CJOSE ${BITBAKE_STAGING_DIR}/xl4bus/libcjose)
    set(CARES ${BITBAKE_STAGING_DIR}/xl4bus/libcares)

    include_directories(SYSTEM ${JSON_C}/include)
    include_directories(SYSTEM ${JSON_C}/include/json-c)
    include_directories(SYSTEM ${MBEDTLS}/include)
    include_directories(SYSTEM ${MBEDTLS}/include/mbedtls)
    include_directories(SYSTEM ${CJOSE}/include)
    include_directories(SYSTEM ${CJOSE}/include/cjose)
    if (XL4_SUPPORT_RESOLVER)
        include_directories(SYSTEM ${CARES}/include)
    endif()
else(ENABLE_YOCTO_BUILD)
    set(JSON_C ${CMAKE_CURRENT_SOURCE_DIR}/json-c-build)
    set(MBEDTLS ${CMAKE_CURRENT_SOURCE_DIR}/mbedtls-build)
    set(CJOSE ${CMAKE_CURRENT_SOURCE_DIR}/cjose-build)
    set(CARES ${CMAKE_CURRENT_SOURCE_DIR}/c-ares-build)

    include_directories(SYSTEM ${JSON_C})
    include_directories(SYSTEM ${MBEDTLS}/include)
    include_directories(SYSTEM ${CJOSE}/include)
    if (XL4_SUPPORT_RESOLVER)
        include_directories(SYSTEM ${CARES})
    endif()
endif(ENABLE_YOCTO_BUILD)

set(LIB_SOURCE ${LIB_SOURCE}
    PHONY
    ${BCH}
    ${BUILD_INCLUDE_BUS}/types_base.h
    ${CMAKE_CURRENT_BINARY_DIR}/xl4bus_version.h
    src/client_message.h
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
    src/lib/url_decode.c
    src/lib/url_decode.h
    src/basics.h
    src/basics.c
    src/lib/hash_list.h
    src/renamed_json.h
    src/fragments/linux_if_bind.h
    src/xl4_vasprintf.h
    src/xl4_vasprintf.c
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
    set_empty(NEED_PTHREADS TRUE)
    if (NEED_PTHREADS)
      set_empty(THREADS_PREFER_PTHREAD_FLAG TRUE)
      find_package(Threads MODULE REQUIRED)
    endif()
endif()

if (BUILD_SHARED)
    add_library(xl4bus-shared SHARED ${LIB_SOURCE})
    set_target_properties(xl4bus-shared PROPERTIES OUTPUT_NAME xl4bus CLEAN_DIRECT_OUTPUT 1)
    if (XL4_PROVIDE_THREADS)
        target_link_libraries(xl4bus-shared Threads::Threads)
    endif()
    set(USE_LIB xl4bus-shared)
    target_link_libraries(xl4bus-shared ${SHARED_LIBS})
    target_compile_definitions(xl4bus-shared PRIVATE XL4BUS_BUILD)
    install(TARGETS xl4bus-shared LIBRARY DESTINATION lib COMPONENT SharedLibrary)

    if(ENABLE_YOCTO_BUILD)
        set_target_properties(xl4bus-shared PROPERTIES
            SOVERSION   ${PROJECT_VERSION_MAJOR}
            VERSION     ${PROJECT_VERSION}
            )
    endif(ENABLE_YOCTO_BUILD)
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
    install(TARGETS xl4bus-static ARCHIVE DESTINATION lib COMPONENT StaticLibrary)
endif()

if (BUILD_BINS)

    set(BIN_LIB_SRC
        src/lib/common.h
        src/lib/common.c
        src/lib/debug.h
        src/lib/debug.c
        src/lib/rb_tree.h
        src/lib/rb_tree.c
        src/lib/url_decode.c
        src/lib/url_decode.h
        src/basics.h
        src/basics.c
        src/porting.h
        src/xl4_vasprintf.h
        src/xl4_vasprintf.c
        src/lib/xl4_epoll.h
        src/lib/xl4_epoll.c
        src/lib/xl4_tablefd.h
        src/lib/xl4_tablefd.c
        ${PORT_SOURCE}
    )

    add_executable(ll-client
            src/test_clients/ll-client.c
            ${BIN_LIB_SRC}
        )

    set(BROKER_SRC
            src/broker/broker.h
            src/broker/bus.c
            src/broker/crypto.c
            src/broker/e900.c
            src/broker/gather.c
            src/lib/hash_list.h
            src/broker/hash_tree.c
            src/broker/broker.c
            src/fragments/linux_if_bind.h
            src/uthash.h
            src/utarray.h
            ${BIN_LIB_SRC}
            )

    set(BROKER_BIN_SRC
            ${BROKER_SRC}
            src/broker/broker_main.c )

    add_executable(xl4bus-broker ${BROKER_BIN_SRC})

    if (RUN_TESTS)
        add_executable(xl4bus-broker-untested ${BROKER_BIN_SRC})
    endif()

    add_executable(tree-test
        src/tests/tree.c
        ${BIN_LIB_SRC}
        )

    set(TEST_BINARIES "tree-test")

    add_executable(timeout-test
            src/tests/timeout.c
            ${BIN_LIB_SRC}
            )
    set(TEST_BINARIES ${TEST_BINARIES} "timeout-test")

    set(NORMAL_BINARIES "ll-client" "xl4bus-broker" "xl4bus-broker-untested")

    if (XL4_PROVIDE_THREADS)

        set(THREADED_BINARIES ${THREADED_BINARIES} ll-server hl-client)

        add_executable(ll-server
                src/test_clients/ll-server.c
                ${BIN_LIB_SRC}
            )
        add_executable(hl-client
                src/test_clients/hl-client.c
                ${BIN_LIB_SRC}
            )

        if (XL4_FULL_TEST AND BUILD_SHARED)

            aux_source_directory(src/tests/embedded EMBEDDED_TEST_CODE)

            # let's build our own version of the shared library,
            # because we'll have some testing code built into it.
            add_library(xl4bus-shared-test SHARED ${LIB_SOURCE} ${EMBEDDED_TEST_CODE})
            set_target_properties(xl4bus-shared-test PROPERTIES OUTPUT_NAME xl4bus-test CLEAN_DIRECT_OUTPUT 1)
            set(THREADED_BINARIES ${THREADED_BINARIES} xl4bus-shared-test)
            target_link_libraries(xl4bus-shared-test ${SHARED_LIBS})
            target_compile_definitions(xl4bus-shared-test PRIVATE XL4BUS_BUILD)
            target_compile_definitions(xl4bus-shared-test PRIVATE WITH_UNIT_TEST)
            target_compile_definitions(xl4bus-shared-test PRIVATE XL4_CLIENT_RECONNECT_INTERVAL_MS=300)
            set(USE_TEST_LIB xl4bus-shared-test)

            aux_source_directory(src/tests/cases TEST_CASES)
            add_executable(full-test
                src/tests/full-test.c
                src/tests/full-test.h
                ${BROKER_SRC}
                ${TEST_CASES}
                ${BIN_LIB_SRC}
            )

            # target_link_libraries(full-test xl4bus-shared-test)
            target_link_libraries(full-test ${JSON_C_LIB})

            set(TEST_BINARIES ${TEST_BINARIES} "full-test")
            set(THREADED_BINARIES ${THREADED_BINARIES} "full-test")
            target_compile_definitions(full-test PRIVATE WITH_UNIT_TEST)
        endif()

        targets_link_libraries(${THREADED_BINARIES} LIBRARIES Threads::Threads)
        set(NORMAL_BINARIES ${NORMAL_BINARIES} ${THREADED_BINARIES})
    else()
        message(WARNING "Some binaries require threading support, those binaries have not been built")
    endif()

    set(BINARIES ${NORMAL_BINARIES} ${TEST_BINARIES})

    install(TARGETS xl4bus-broker RUNTIME DESTINATION bin COMPONENT Broker)

    target_link_libraries(xl4bus-broker ${JSON_C_LIB})

    if (WITH_EFENCE)
        targets_link_libraries(${BINARIES} LIBRARIES -lefence)
    endif()

    targets_link_libraries(${NORMAL_BINARIES} LIBRARIES ${USE_LIB})
    if (NOT USE_TEST_LIB)
        set(USE_TEST_LIB ${USE_LIB})
    endif()
    targets_link_libraries(${TEST_BINARIES} LIBRARIES ${USE_TEST_LIB})

endif()

install(DIRECTORY src/include/libxl4bus DESTINATION include COMPONENT PublicHeaders)
install(FILES ${BCH} DESTINATION include/libxl4bus COMPONENT PublicHeaders)
install(FILES ${BUILD_INCLUDE_BUS}/types_base.h ${BUILD_INCLUDE_BUS}/build_config.h DESTINATION include/libxl4bus COMPONENT PublicHeaders)

find_package(Doxygen)

if (NOT DOXYGEN_FOUND)

    message(WARNING "Doxygen is needed to build the documentation, skipping documentation build now")

else ()

    set(doxyfile_in ${CMAKE_CURRENT_SOURCE_DIR}/doc/doxyfile.in)
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

    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html DESTINATION share/doc/libxl4bus COMPONENT HTMLDocuments)

endif ()

if (RUN_TESTS)
    if (BUILD_BINS)
        enable_testing()
        add_test(NAME unit-tree COMMAND tree-test)
        add_test(NAME unit-timeout COMMAND timeout-test)
        set_tests_properties(unit-tree unit-timeout PROPERTIES TIMEOUT 600)
        if (XL4_FULL_TEST)
            add_test(NAME unit-full-prepare
                WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
                COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/src/tests/prepare-full-test.sh ${CMAKE_CURRENT_BINARY_DIR})
            add_test(NAME unit-full-test COMMAND full-test -O full-test.log)
            set_tests_properties(unit-full-prepare unit-full-test PROPERTIES TIMEOUT 6000)
            set_tests_properties(unit-full-test PROPERTIES DEPENDS "unit-full-prepare")
        endif()
        add_custom_command(
            TARGET xl4bus-broker
            DEPENDS ${TEST_BINARIES}
            COMMENT "Run tests"
            POST_BUILD
            WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
            COMMAND ${CMAKE_CTEST_COMMAND} -C $<CONFIGURATION> -V -R "^unit-"
        )

        add_dependencies(xl4bus-broker ${TEST_BINARIES})

    endif()
else()
    message(WARNING "Please remember to run tests on the target platform!")
endif()

include(${LOAD_CFG})

#-----------------------------------------------------------------------------
# Setup Packaging Config
#-----------------------------------------------------------------------------
add_subdirectory(pkg)
