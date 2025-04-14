# Copy topology file
configure_file(topology.json ${CMAKE_CURRENT_BINARY_DIR}/topology.json COPYONLY)

add_executable(paths_example paths.c)
target_link_libraries(paths_example PRIVATE scion)

add_executable(ping_example ping.c)
target_link_libraries(ping_example PRIVATE scion)

add_executable(server_example server.c)
target_link_libraries(server_example PRIVATE scion)

add_executable(choose_path_example choose_path.c)
target_link_libraries(choose_path_example PRIVATE scion)

add_executable(udp_example udp.c)
target_link_libraries(udp_example PRIVATE scion)

add_executable(features_example features.c)
target_link_libraries(features_example PRIVATE scion)

add_executable(scmp_error_example scmp_error.c)
target_link_libraries(scmp_error_example PRIVATE scion)

add_executable(scmp_error_generator_example scmp_error_generator.c)
target_link_libraries(scmp_error_generator_example PRIVATE scion)

option(LIBEV_DIR "path of libev (must contain libev.so)")
option(OPENSSL_DIR "path of openssl (must contain lib/libssl.so and lib/libcrypto.so")

# Fetch ngtcp2
ExternalProject_Add(
        ngtcp2
        GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
        GIT_TAG v1.11.0
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/dependencies -DENABLE_SHARED_LIB=OFF -DBUILD_TESTING=OFF -DOPENSSL_ROOT_DIR=${OPENSSL_DIR} -DENABLE_DEBUG=ON
)

add_executable(simple_quic_client simple_quic_client.c)
target_include_directories(simple_quic_client PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/dependencies/include)

add_dependencies(simple_quic_client ngtcp2)
target_link_libraries(simple_quic_client PRIVATE
        scion
        ${CMAKE_CURRENT_BINARY_DIR}/dependencies/lib/libngtcp2.a
        ${CMAKE_CURRENT_BINARY_DIR}/dependencies/lib/libngtcp2_crypto_quictls.a
        ${OPENSSL_DIR}/lib/libssl.so
        ${OPENSSL_DIR}/lib/libcrypto.so
        ${LIBEV_DIR}/libev.so
)