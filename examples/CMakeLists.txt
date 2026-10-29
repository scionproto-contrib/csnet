set(DEPENDENCY_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/dependencies)

# The dependencies that use make would otherwise be built with one job.
cmake_host_system_information(RESULT JOBS QUERY NUMBER_OF_LOGICAL_CORES)

# The same goes for the dependencies that use configure scripts and make, which take the compiler from CC.
if (CMAKE_C_COMPILER_LAUNCHER)
    string(JOIN " " DEPENDENCY_CC ${CMAKE_C_COMPILER_LAUNCHER} ${CMAKE_C_COMPILER})
    set(DEPENDENCY_ENV ${CMAKE_COMMAND} -E env "CC=${DEPENDENCY_CC}")
endif ()

add_executable(bootstrapper_example bootstrapper.c)
target_link_libraries(bootstrapper_example PRIVATE scion)

add_executable(paths_example paths.c)
target_link_libraries(paths_example PRIVATE scion)

add_executable(choose_path_example choose_path.c)
target_link_libraries(choose_path_example PRIVATE scion)

add_executable(udp_example udp.c)
target_link_libraries(udp_example PRIVATE scion)

add_executable(features_example features.c)
target_link_libraries(features_example PRIVATE scion)

add_executable(policy_example policy.c)
target_link_libraries(policy_example PRIVATE scion)

add_executable(selector_example selector.c)
target_link_libraries(selector_example PRIVATE scion)

add_executable(server_example server.c)
target_link_libraries(server_example PRIVATE scion)

add_executable(scmp_error_example scmp_error.c)
target_link_libraries(scmp_error_example PRIVATE scion)

add_executable(scmp_error_generator_example scmp_error_generator.c)
target_link_libraries(scmp_error_generator_example PRIVATE scion)

add_executable(messages_example messages.c)
target_link_libraries(messages_example PRIVATE scion)

add_executable(timestamps_example timestamps.c)
target_link_libraries(timestamps_example PRIVATE scion)

# Fetch libev
ExternalProject_Add(
        libev
        GIT_REPOSITORY https://github.com/enki/libev.git
        GIT_TAG master
        GIT_SHALLOW TRUE
        UPDATE_DISCONNECTED TRUE
        CONFIGURE_COMMAND ${DEPENDENCY_ENV} ./configure --prefix=${DEPENDENCY_INSTALL_DIR} --disable-shared
        BUILD_COMMAND make -j${JOBS}
        INSTALL_COMMAND make install
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS ${DEPENDENCY_INSTALL_DIR}/lib/libev.a
)

# Fetch quictls
ExternalProject_Add(
        quictls
        GIT_REPOSITORY https://github.com/quictls/openssl.git
        GIT_TAG OpenSSL_1_1_1w+quic
        GIT_SHALLOW TRUE
        UPDATE_DISCONNECTED TRUE
        CONFIGURE_COMMAND ${DEPENDENCY_ENV} ./config --prefix=${DEPENDENCY_INSTALL_DIR} --openssldir=${DEPENDENCY_INSTALL_DIR}/ssl no-shared no-tests
        BUILD_COMMAND make -j${JOBS}
        INSTALL_COMMAND make install_sw
        BUILD_IN_SOURCE 1
        BUILD_BYPRODUCTS ${DEPENDENCY_INSTALL_DIR}/lib/libssl.a ${DEPENDENCY_INSTALL_DIR}/lib/libcrypto.a
)

# Fetch ngtcp2
ExternalProject_Add(
        ngtcp2
        GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
        GIT_TAG v1.12.0
        GIT_SHALLOW TRUE
        UPDATE_DISCONNECTED TRUE
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${DEPENDENCY_INSTALL_DIR} -DENABLE_LIB_ONLY=ON -DENABLE_SHARED_LIB=OFF -DBUILD_TESTING=OFF -DOPENSSL_ROOT_DIR=${DEPENDENCY_INSTALL_DIR} -DLIBEV_INCLUDE_DIR=${DEPENDENCY_INSTALL_DIR}/include -DLIBEV_LIBRARY=${DEPENDENCY_INSTALL_DIR}/lib -DENABLE_DEBUG=ON ${DEPENDENCY_LAUNCHER_ARGS}
        BUILD_BYPRODUCTS ${DEPENDENCY_INSTALL_DIR}/lib/libngtcp2.a ${DEPENDENCY_INSTALL_DIR}/lib/libngtcp2_crypto_quictls.a
)
add_dependencies(ngtcp2 libev quictls)

add_executable(simple_quic_client simple_quic_client.c)
target_include_directories(simple_quic_client PRIVATE ${DEPENDENCY_INSTALL_DIR}/include)

add_dependencies(simple_quic_client ngtcp2)
target_link_libraries(simple_quic_client PRIVATE
        scion
        ${DEPENDENCY_INSTALL_DIR}/lib/libngtcp2.a
        ${DEPENDENCY_INSTALL_DIR}/lib/libngtcp2_crypto_quictls.a
        ${DEPENDENCY_INSTALL_DIR}/lib/libev.a
        ${DEPENDENCY_INSTALL_DIR}/lib/libssl.a
        ${DEPENDENCY_INSTALL_DIR}/lib/libcrypto.a
        m
)