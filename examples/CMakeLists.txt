set(DEPENDENCY_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/dependencies)

# Copy topology file
configure_file(topology.json ${CMAKE_CURRENT_BINARY_DIR}/topology.json COPYONLY)

add_executable(paths_example paths.c)
target_link_libraries(paths_example PRIVATE scion)
add_test(NAME fetch_paths COMMAND paths_example)
set_tests_properties(fetch_paths PROPERTIES LABELS "e2e")

add_executable(ping_example ping.c)
target_link_libraries(ping_example PRIVATE scion)
add_test(NAME ping COMMAND ping_example)
set_tests_properties(ping PROPERTIES LABELS "e2e")

add_executable(choose_path_example choose_path.c)
target_link_libraries(choose_path_example PRIVATE scion)
add_test(NAME choose_path COMMAND choose_path_example)
set_tests_properties(choose_path PROPERTIES LABELS "e2e")

add_executable(udp_example udp.c)
target_link_libraries(udp_example PRIVATE scion)
add_test(NAME udp COMMAND udp_example)
set_tests_properties(udp PROPERTIES LABELS "e2e")

add_executable(features_example features.c)
target_link_libraries(features_example PRIVATE scion)
add_test(NAME features COMMAND features_example)
set_tests_properties(features PROPERTIES LABELS "e2e")

if (BUILD_EXAMPLES)
    add_executable(server_example server.c)
    target_link_libraries(server_example PRIVATE scion)

    add_executable(scmp_error_example scmp_error.c)
    target_link_libraries(scmp_error_example PRIVATE scion)

    add_executable(scmp_error_generator_example scmp_error_generator.c)
    target_link_libraries(scmp_error_generator_example PRIVATE scion)

    # Fetch libev
    ExternalProject_Add(
            libev
            GIT_REPOSITORY https://github.com/enki/libev.git
            GIT_TAG master
            CONFIGURE_COMMAND ./configure --prefix=${DEPENDENCY_INSTALL_DIR} --disable-shared
            BUILD_COMMAND make
            INSTALL_COMMAND make install
            BUILD_IN_SOURCE 1
            BUILD_BYPRODUCTS ${DEPENDENCY_INSTALL_DIR}/lib/libev.a
    )

    # Fetch quictls
    ExternalProject_Add(
            quictls
            GIT_REPOSITORY https://github.com/quictls/openssl.git
            GIT_TAG OpenSSL_1_1_1w+quic
            CONFIGURE_COMMAND ./config --prefix=${DEPENDENCY_INSTALL_DIR} --openssldir=${DEPENDENCY_INSTALL_DIR}/ssl no-shared
            BUILD_COMMAND make
            INSTALL_COMMAND make install_sw
            BUILD_IN_SOURCE 1
            BUILD_BYPRODUCTS ${DEPENDENCY_INSTALL_DIR}/lib/libssl.a ${DEPENDENCY_INSTALL_DIR}/lib/libcrypto.a
    )

    # Fetch ngtcp2
    ExternalProject_Add(
            ngtcp2
            GIT_REPOSITORY https://github.com/ngtcp2/ngtcp2.git
            GIT_TAG v1.12.0
            CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${DEPENDENCY_INSTALL_DIR} -DENABLE_LIB_ONLY=ON -DENABLE_SHARED_LIB=OFF -DBUILD_TESTING=OFF -DOPENSSL_ROOT_DIR=${DEPENDENCY_INSTALL_DIR} -DLIBEV_INCLUDE_DIR=${DEPENDENCY_INSTALL_DIR}/include -DLIBEV_LIBRARY=${DEPENDENCY_INSTALL_DIR}/lib -DENABLE_DEBUG=ON
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
    )
endif ()