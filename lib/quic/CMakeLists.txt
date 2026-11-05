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

# scion_quic: QUIC client connections over SCION (ngtcp2 + a TLS backend), see scion/scion_quic.h.
#
#   -DSCION_QUIC_TLS=picotls   picotls with mbedTLS (Apache-2.0/MIT, the backend of the ESP32 build), default
#   -DSCION_QUIC_TLS=quictls   quictls (OpenSSL 1.1.1 with the QUIC API)

set(SCION_QUIC_TLS "picotls" CACHE STRING "TLS backend of scion_quic: picotls (with mbedTLS) or quictls")
set_property(CACHE SCION_QUIC_TLS PROPERTY STRINGS picotls quictls)
if (NOT SCION_QUIC_TLS MATCHES "^(picotls|quictls)$")
    message(FATAL_ERROR "SCION_QUIC_TLS must be picotls or quictls, not ${SCION_QUIC_TLS}")
endif ()

set(QUIC_DEPS_DIR ${CMAKE_CURRENT_BINARY_DIR}/dependencies)
cmake_host_system_information(RESULT JOBS QUERY NUMBER_OF_LOGICAL_CORES)
if (CMAKE_C_COMPILER_LAUNCHER) # configure scripts take the compiler (and launcher) from CC
    string(JOIN " " DEPENDENCY_CC ${CMAKE_C_COMPILER_LAUNCHER} ${CMAKE_C_COMPILER})
    set(DEPENDENCY_ENV ${CMAKE_COMMAND} -E env "CC=${DEPENDENCY_CC}")
endif ()

# ngtcp2 is compiled from its sources (see cmake/Ngtcp2Sources.cmake)
FetchContent_Declare(ngtcp2_src
        GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
        GIT_TAG v1.12.0
        GIT_SHALLOW TRUE
        SOURCE_SUBDIR no-cmake) # only the sources, not ngtcp2's own build
FetchContent_MakeAvailable(ngtcp2_src)
include(Ngtcp2Sources)
scion_ngtcp2_sources(${ngtcp2_src_SOURCE_DIR} ${SCION_QUIC_TLS} ${CMAKE_CURRENT_BINARY_DIR}/ngtcp2_gen)

add_library(scion_quic STATIC quic.c tls_${SCION_QUIC_TLS}.c ${NGTCP2_SOURCES})
# The private include directories of scion_quic (ngtcp2, the TLS library), for the tests in tests/unit/quic
add_library(scion_quic_internal INTERFACE)
target_include_directories(scion_quic PUBLIC ../include PRIVATE ${NGTCP2_INCLUDE_DIRS})
target_compile_definitions(scion_quic PRIVATE ${NGTCP2_DEFINITIONS})
target_include_directories(scion_quic_internal INTERFACE ${NGTCP2_INCLUDE_DIRS})
target_compile_definitions(scion_quic_internal INTERFACE ${NGTCP2_DEFINITIONS})
target_link_libraries(scion_quic PUBLIC scion)
set_source_files_properties(${NGTCP2_SOURCES} PROPERTIES COMPILE_OPTIONS -w)

if (SCION_QUIC_TLS STREQUAL "picotls")
    # mbedTLS 4.1 (the version of ESP-IDF 6.1), crypto through PSA
    ExternalProject_Add(mbedtls
            GIT_REPOSITORY https://github.com/Mbed-TLS/mbedtls.git
            GIT_TAG mbedtls-4.1.0
            GIT_SHALLOW TRUE
            GIT_SUBMODULES_RECURSE TRUE
            UPDATE_DISCONNECTED TRUE
            CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${QUIC_DEPS_DIR} -DCMAKE_BUILD_TYPE=Release -DENABLE_PROGRAMS=OFF
            -DENABLE_TESTING=OFF -DMBEDTLS_FATAL_WARNINGS=OFF -DCMAKE_POSITION_INDEPENDENT_CODE=ON
            ${DEPENDENCY_LAUNCHER_ARGS}
            BUILD_BYPRODUCTS ${QUIC_DEPS_DIR}/lib/libmbedtls.a ${QUIC_DEPS_DIR}/lib/libmbedx509.a
            ${QUIC_DEPS_DIR}/lib/libtfpsacrypto.a)

    FetchContent_Declare(picotls_src
            GIT_REPOSITORY https://github.com/h2o/picotls.git
            GIT_TAG 0729692aa977ad8bfcca21884915cb3d22a1d285 # no releases, pinned commit (2026-11-04)
            # picotls passes SIZE_MAX as AEAD output size, which fails with mbedTLS >= 3.6 (to be sent upstream)
            PATCH_COMMAND sh -c "git apply --reverse --check ${CMAKE_CURRENT_SOURCE_DIR}/patches/picotls-mbedtls-aead-output-size.patch 2>/dev/null || git apply ${CMAKE_CURRENT_SOURCE_DIR}/patches/picotls-mbedtls-aead-output-size.patch"
            SOURCE_SUBDIR no-cmake)
    FetchContent_MakeAvailable(picotls_src)
    set(PICOTLS_SOURCES ${picotls_src_SOURCE_DIR}/lib/picotls.c ${picotls_src_SOURCE_DIR}/lib/hpke.c
            ${picotls_src_SOURCE_DIR}/lib/mbedtls.c)
    target_sources(scion_quic PRIVATE ${PICOTLS_SOURCES})
    set_source_files_properties(${PICOTLS_SOURCES} PROPERTIES COMPILE_OPTIONS -w)
    # Shims, searched first: ngtcp2's picotls backend uses the OpenSSL binding of picotls, compat/picotls/openssl.h
    # maps it to mbedTLS; mbedTLS 4 moved/removed two headers that picotls/lib/mbedtls.c includes.
    target_include_directories(scion_quic BEFORE PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/compat
            ${CMAKE_CURRENT_SOURCE_DIR}/compat/mbedtls4)
    # The ChaCha20 API of mbedTLS 4 is private, picotls/lib/mbedtls.c needs it for QUIC header protection
    set_source_files_properties(${picotls_src_SOURCE_DIR}/lib/mbedtls.c PROPERTIES
            COMPILE_DEFINITIONS MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS)

    add_dependencies(scion_quic mbedtls)
    target_include_directories(scion_quic PRIVATE ${picotls_src_SOURCE_DIR}/include ${QUIC_DEPS_DIR}/include)
    target_include_directories(scion_quic_internal INTERFACE ${picotls_src_SOURCE_DIR}/include ${QUIC_DEPS_DIR}/include)
    # ptls_load_certificates() for the test server
    set(SCION_QUIC_TEST_SOURCES ${picotls_src_SOURCE_DIR}/lib/pembase64.c PARENT_SCOPE)
    target_link_libraries(scion_quic PUBLIC ${QUIC_DEPS_DIR}/lib/libmbedtls.a ${QUIC_DEPS_DIR}/lib/libmbedx509.a
            ${QUIC_DEPS_DIR}/lib/libtfpsacrypto.a)
else ()
    ExternalProject_Add(quictls
            GIT_REPOSITORY https://github.com/quictls/openssl.git
            GIT_TAG OpenSSL_1_1_1w+quic
            GIT_SHALLOW TRUE
            UPDATE_DISCONNECTED TRUE
            CONFIGURE_COMMAND ${DEPENDENCY_ENV} ./config --prefix=${QUIC_DEPS_DIR} --openssldir=${QUIC_DEPS_DIR}/ssl
            no-shared no-tests
            BUILD_COMMAND make -j${JOBS}
            INSTALL_COMMAND make install_sw
            BUILD_IN_SOURCE 1
            BUILD_BYPRODUCTS ${QUIC_DEPS_DIR}/lib/libssl.a ${QUIC_DEPS_DIR}/lib/libcrypto.a)

    add_dependencies(scion_quic quictls)
    target_include_directories(scion_quic PRIVATE ${QUIC_DEPS_DIR}/include)
    target_include_directories(scion_quic_internal INTERFACE ${QUIC_DEPS_DIR}/include)
    target_link_libraries(scion_quic PUBLIC ${QUIC_DEPS_DIR}/lib/libssl.a ${QUIC_DEPS_DIR}/lib/libcrypto.a
            ${CMAKE_DL_LIBS} pthread)
endif ()
