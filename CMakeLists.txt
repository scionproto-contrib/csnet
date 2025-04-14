cmake_minimum_required(VERSION 3.22)
project(csnet C)

option(BUILD_EXAMPLES "build examples" OFF)
option(BUILD_TESTS "build tests" OFF)
option(BUILD_DOCS "build docs" OFF)

set(CMAKE_C_STANDARD 11)
set(ALLOW_DUPLICATE_CUSTOM_TARGETS TRUE)
set(CMAKE_MAKEFILE true)
set(BUILD_TESTING ${BUILD_TESTS})

include(FetchContent)
include(ExternalProject)
include(CTest)

# Add subdirectories
add_subdirectory(lib)

if (BUILD_EXAMPLES)
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
    set(DOXYGEN_HTML_OUTPUT ${CMAKE_SOURCE_DIR}/docs/html)
    set(DOXYGEN_GENERATE_LATEX NO)

    doxygen_add_docs(doxygen
            include/scion/scion.h
            include/scion/error.h
            include/scion/util/linked_list.h
            README.md
    )
endif ()