# Copyright 2026 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# scion_quic (lib/quic) for ESP-IDF: ngtcp2 and picotls compiled from their sources, cryptography from ESP-IDF's
# mbedTLS (hardware accelerated). Same sources and shims as the Linux build with -DSCION_QUIC_TLS=picotls.
set(CSNET_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..)
get_filename_component(CSNET_DIR ${CSNET_DIR} ABSOLUTE)

# The early expansion of ESP-IDF only collects the requirements, fetching happens in the real configuration.
if (CMAKE_BUILD_EARLY_EXPANSION OR NOT CONFIG_CSNET_QUIC)
    idf_component_register(REQUIRES mbedtls lwip)
    return()
endif ()

include(FetchContent)
FetchContent_Declare(ngtcp2_src
        GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
        GIT_TAG v1.12.0
        GIT_SHALLOW TRUE
        SOURCE_SUBDIR no-cmake)
FetchContent_Declare(picotls_src
        GIT_REPOSITORY https://github.com/h2o/picotls.git
        GIT_TAG 0729692aa977ad8bfcca21884915cb3d22a1d285
        # picotls passes SIZE_MAX as AEAD output size, which fails with mbedTLS >= 3.6 (to be sent upstream)
        PATCH_COMMAND sh -c "git apply --reverse --check ${CSNET_DIR}/lib/quic/patches/picotls-mbedtls-aead-output-size.patch 2>/dev/null || git apply ${CSNET_DIR}/lib/quic/patches/picotls-mbedtls-aead-output-size.patch"
        SOURCE_SUBDIR no-cmake)
FetchContent_MakeAvailable(ngtcp2_src picotls_src)

include(${CSNET_DIR}/cmake/Ngtcp2Sources.cmake)
scion_ngtcp2_sources(${ngtcp2_src_SOURCE_DIR} picotls ${CMAKE_CURRENT_BINARY_DIR}/ngtcp2_gen)
set(PICOTLS_SOURCES ${picotls_src_SOURCE_DIR}/lib/picotls.c ${picotls_src_SOURCE_DIR}/lib/hpke.c
        ${picotls_src_SOURCE_DIR}/lib/mbedtls.c)

idf_component_register(
        SRCS ${CSNET_DIR}/lib/quic/quic.c ${CSNET_DIR}/lib/quic/tls_picotls.c ${NGTCP2_SOURCES} ${PICOTLS_SOURCES}
        INCLUDE_DIRS ${CSNET_DIR}/lib/include
        PRIV_INCLUDE_DIRS ${NGTCP2_INCLUDE_DIRS} ${picotls_src_SOURCE_DIR}/include
        REQUIRES mbedtls lwip)

target_compile_definitions(${COMPONENT_LIB} PRIVATE ${NGTCP2_DEFINITIONS})
# Shims searched first (see lib/quic/CMakeLists.txt); compat/mbedtls4 only for mbedTLS >= 4 (ESP-IDF >= 6)
set(COMPAT ${CSNET_DIR}/lib/quic/compat)
if (IDF_VERSION_MAJOR GREATER_EQUAL 6)
    list(APPEND COMPAT ${CSNET_DIR}/lib/quic/compat/mbedtls4)
    set_source_files_properties(${picotls_src_SOURCE_DIR}/lib/mbedtls.c PROPERTIES
            COMPILE_DEFINITIONS MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS)
endif ()
target_include_directories(${COMPONENT_LIB} BEFORE PRIVATE ${COMPAT})
set_source_files_properties(${NGTCP2_SOURCES} ${PICOTLS_SOURCES} PROPERTIES COMPILE_OPTIONS -w)

# The SCION library (lib/) is compiled into the main component of this project, which in turn uses scion_quic:
# link both ways (circular dependency, see the ESP-IDF build system documentation).
idf_component_get_property(main_lib main COMPONENT_LIB)
target_link_libraries(${COMPONENT_LIB} INTERFACE ${main_lib})
set_property(TARGET ${COMPONENT_LIB} APPEND PROPERTY LINK_INTERFACE_MULTIPLICITY 3)
