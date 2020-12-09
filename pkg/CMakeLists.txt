###############################################################################
# XL4BUS Package Build Configurations
###############################################################################
cmake_minimum_required(VERSION 3.5 FATAL_ERROR)

#----------------------
# General Package Settings
#----------------------
# set default cpack package name
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})

# executing 'make package' will create both deb and tgz packages
set(CPACK_GENERATOR DEB TGZ)

# set packager's contact (email), this is required for deb package generator
set(CPACK_PACKAGE_CONTACT "<>")

# set package destination
set(CPACK_PACKAGE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})

# set the group for each component (CPACK_COMPONENT_<compName>_GROUP)
# where <compName> is the COMPONENT info in each install() call in all caps
set(CPACK_COMPONENT_STATICLIBRARY_GROUP lib)
set(CPACK_COMPONENT_SHAREDLIBRARY_GROUP lib)
set(CPACK_COMPONENT_LIBTOOLFILE_GROUP   lib)
set(CPACK_COMPONENT_BROKER_GROUP        brk)
set(CPACK_COMPONENT_PUBLICHEADERS_GROUP dev)
set(CPACK_COMPONENT_HTMLDOCUMENTS_GROUP doc)

# set PKG_ARCH_STR used for package name base on compiler arch
if(NOT DEFINED BUILD_ARCH OR BUILD_ARCH STREQUAL "")
    set(PKG_ARCH_STR "amd64")
else()
    if(BUILD_ARCH STREQUAL "x86_64")
        set(PKG_ARCH_STR "amd64")
    else()
        set(PKG_ARCH_STR "${BUILD_ARCH}")
    endif()
endif()

#----------------------
# DEB Package Settings
#----------------------
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_DEBIAN_LIB_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_DEBIAN_FILE_NAME DEB-DEFAULT)

set(CPACK_DEBIAN_LIB_DESCRIPTION "Library")
set(CPACK_DEBIAN_DEV_DESCRIPTION "Development files")
set(CPACK_DEBIAN_BRK_DESCRIPTION "Broker")
set(CPACK_DEBIAN_DOC_DESCRIPTION "Documents")

set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS ON)
set(LIB_DEB_PACKAGE_DEPENDS_LIST
    "libssl1.1 (>= 1.1.0)"
    "libjansson4 (>= 2.12)"
    )
set(BRK_DEB_PACKAGE_DEPENDS_LIST "xl4bus (>= 1.0.0)")

string(REPLACE ";" ", " LIB_DEB_PACKAGE_DEPENDS_LIST "${LIB_DEB_PACKAGE_DEPENDS_LIST}")
string(REPLACE ";" ", " BRK_DEB_PACKAGE_DEPENDS_LIST "${BRK_DEB_PACKAGE_DEPENDS_LIST}")

set(CPACK_DEBIAN_LIB_PACKAGE_DEPENDS "${LIB_DEB_PACKAGE_DEPENDS_LIST}")
set(CPACK_DEBIAN_BRK_PACKAGE_DEPENDS "${BRK_DEB_PACKAGE_DEPENDS_LIST}")

set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS ON)
set(CPACK_DEBIAN_PACKAGE_GENERATE_SHLIBS_POLICY ">=")

set(TRIGGERS ${CMAKE_CURRENT_BINARY_DIR}/CMakeDebControlExtra/triggers)
set(CPACK_DEBIAN_LIB_PACKAGE_CONTROL_EXTRA "${TRIGGERS}")

file(WRITE ${TRIGGERS} "activate-noawait ldconfig\n")

#----------------------
# TGZ Package Settings
#----------------------
# Set filename for Archive type packages.
# Although it is already set here we still need to set this to
# CPACK_PACKAGE_FILE_NAME due to the following issue
# - https://gitlab.kitware.com/cmake/cmake/issues/20419
set(CPACK_ARCHIVE_FILE_NAME ${PROJECT_NAME}_${PROJECT_VERSION}_${PKG_ARCH_STR})
set(CPACK_PACKAGE_FILE_NAME ${CPACK_ARCHIVE_FILE_NAME})

#----------------------
# Setup 'package' target
# (All CPACK_XXX settings before this call will be use in the target setup)
#----------------------
include(CPack)

#----------------------
# Setup custom (deb, tgz) targets
# (Targets to generate specific package type)
#----------------------
set(DEB_PACKAGES
    ${CMAKE_CURRENT_BINARY_DIR}/${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_${PKG_ARCH_STR}.deb
    ${CMAKE_CURRENT_BINARY_DIR}/${CPACK_PACKAGE_NAME}-dev_${CPACK_PACKAGE_VERSION}_${PKG_ARCH_STR}.deb
    ${CMAKE_CURRENT_BINARY_DIR}/${CPACK_PACKAGE_NAME}-brk_${CPACK_PACKAGE_VERSION}_${PKG_ARCH_STR}.deb
    )

set(TGZ_PACKAGES ${CMAKE_CURRENT_BINARY_DIR}/${CPACK_ARCHIVE_FILE_NAME}.tar.gz)

set(TARGET_PACKAGE_DEPENDENCIES xl4bus-shared xl4bus-static xl4bus-broker)

find_package(Doxygen)
if (NOT DOXYGEN_FOUND)
    list(APPEND DEB_PACKAGES ${CMAKE_CURRENT_BINARY_DIR}/${CPACK_PACKAGE_NAME}-doc_${CPACK_PACKAGE_VERSION}_${PKG_ARCH_STR}.deb)
    list(APPEND TARGET_PACKAGE_DEPENDENCIES doc)
endif()

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(TARGET_DEB deb)
    set(TARGET_TGZ tgz)
else()
    set(TARGET_DEB ${PROJECT_NAME}-deb)
    set(TARGET_TGZ ${PROJECT_NAME}-tgz)
endif()

add_custom_command(OUTPUT ${DEB_PACKAGES}
    COMMAND ${CMAKE_CPACK_COMMAND} -D CPACK_GENERATOR=DEB
    DEPENDS ${TARGET_PACKAGE_DEPENDENCIES}
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    COMMENT "Generating ${DEB_PACKAGES}..."
    )

add_custom_target(${TARGET_DEB} DEPENDS ${DEB_PACKAGES})

add_custom_command(OUTPUT ${TGZ_PACKAGES}
    COMMAND ${CMAKE_CPACK_COMMAND} -D CPACK_GENERATOR=TGZ
    DEPENDS ${TARGET_PACKAGE_DEPENDENCIES}
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
    COMMENT "Generating ${TGZ_PACKAGES}..."
    )

add_custom_target(${TARGET_TGZ} DEPENDS ${TGZ_PACKAGES})
