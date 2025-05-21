cmake_minimum_required(VERSION 3.22)
project(csnet C)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

include(FetchContent)
include(ExternalProject)
include(CTest)
include(ExtractValidFlags)

option(BUILD_LIB "build lib" ON)
option(BUILD_CMD "build command line tools" ON)
option(BUILD_TESTS "build tests" OFF)
option(BUILD_EXAMPLES "build examples" OFF)
option(BUILD_DOCS "build docs" OFF)

# Copy topology file
if (EXISTS "${CMAKE_SOURCE_DIR}/topology/topology.json")
    configure_file(topology/topology.json ${CMAKE_CURRENT_BINARY_DIR}/topology/topology.json COPYONLY)
else ()
    configure_file(topology/topology.default.json ${CMAKE_CURRENT_BINARY_DIR}/topology/topology.json COPYONLY)
endif ()

set(CMAKE_C_STANDARD 11)
set(ALLOW_DUPLICATE_CUSTOM_TARGETS TRUE)
set(CMAKE_MAKEFILE true)
set(BUILD_TESTING ${BUILD_TESTS})

if (BUILD_LIB OR BUILD_CMD OR BUILD_TESTS OR BUILD_EXAMPLES)
    add_subdirectory(lib)
endif ()

if (BUILD_CMD OR BUILD_TESTING)
    add_subdirectory(cmd)
endif ()

if (BUILD_EXAMPLES OR BUILD_TESTING)
    add_subdirectory(examples)
endif ()

if (BUILD_TESTING)
    add_subdirectory(tests)
endif ()

if (BUILD_DOCS)
    # CSNET public docs
    include(FindDoxygen)

    find_package(Doxygen REQUIRED doxygen)

    set(DOXYGEN_SORT_MEMBER_DOCS NO)
    set(DOXYGEN_HTML_OUTPUT ${CMAKE_SOURCE_DIR}/docs/api)
    set(DOXYGEN_GENERATE_LATEX NO)
    set(DOXYGEN_USE_MDFILE_AS_MAINPAGE ${CMAKE_SOURCE_DIR}/README.md)
    set(DOXYGEN_OPTIMIZE_OUTPUT_FOR_C YES)
    set(DOXYGEN_INCLUDE_GRAPH NO)
    set(DOXYGEN_SHOW_INCLUDE_FILES NO)

    doxygen_add_docs(doxygen
            lib/include/scion/scion.h
            README.md
            docs/getting-started.md
            examples/README.md
            esp32/README.md
            docs/design/source_address_determination.md
            ALL
    )
endif ()