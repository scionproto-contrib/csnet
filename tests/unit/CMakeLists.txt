set(DEPENDENCY_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/dependencies)

# Fetch cmocka (https://cmocka.org/), a unit testing framework for C.
ExternalProject_Add(
        cmocka
        GIT_REPOSITORY https://gitlab.com/cmocka/cmocka.git
        GIT_TAG cmocka-2.0.2
        GIT_SHALLOW TRUE
        UPDATE_DISCONNECTED TRUE
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${DEPENDENCY_INSTALL_DIR} -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DWITH_EXAMPLES=OFF ${DEPENDENCY_LAUNCHER_ARGS}
        BUILD_BYPRODUCTS ${DEPENDENCY_INSTALL_DIR}/lib/libcmocka.a
)

# Declare test executable
add_executable(unit_tests
        cmocka_main.c
        common/test_hop_field.c
        common/test_info_field.c
        common/test_isd_as.c
        control_plane/test_graph.c
        control_plane/test_path_metadata.c
        control_plane/test_policy.c
        control_plane/test_segment.c
        control_plane/test_topology.c
        data_plane/test_packet.c
        data_plane/test_path.c
        data_plane/socket_fixture.c
        data_plane/test_scmp.c
        data_plane/test_selector.c
        data_plane/test_socket.c
        data_plane/test_timestamp.c
        data_plane/test_udp.c
        data_plane/test_underlay.c
        util/test_addr.c
        util/test_list.c
        util/test_map.c
)
add_dependencies(unit_tests cmocka)

target_compile_definitions(unit_tests PRIVATE
        TEST_TOPOLOGY_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/control_plane/testdata"
)

# Link SCION library and cmocka to tests
target_link_libraries(unit_tests PRIVATE scion ${DEPENDENCY_INSTALL_DIR}/lib/libcmocka.a)

# Give tests access to internal headers and to cmocka's
target_include_directories(unit_tests PRIVATE ${PROJECT_SOURCE_DIR}/lib ${DEPENDENCY_INSTALL_DIR}/include)

add_test(NAME unit_tests COMMAND unit_tests)
set_tests_properties(unit_tests PROPERTIES LABELS "unit")

# The tests of the QUIC library (-DBUILD_QUIC=ON), compiled separately as they need the headers of ngtcp2 and of the
# TLS library, and run by the same executable
if (BUILD_QUIC)
    add_library(quic_tests OBJECT
            quic/test_quic.c
            quic/quic_test_server.c
            quic/quic_test_tls_${SCION_QUIC_TLS}.c
            ${SCION_QUIC_TEST_SOURCES}
    )
    add_dependencies(quic_tests cmocka)
    target_compile_definitions(quic_tests PRIVATE QUIC_TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/quic/testdata")
    target_include_directories(quic_tests PRIVATE ${PROJECT_SOURCE_DIR}/lib ${DEPENDENCY_INSTALL_DIR}/include
            ${CMAKE_CURRENT_SOURCE_DIR})
    target_link_libraries(quic_tests PRIVATE scion_quic scion_quic_internal)
    set_source_files_properties(${SCION_QUIC_TEST_SOURCES} PROPERTIES COMPILE_OPTIONS -w)

    target_compile_definitions(unit_tests PRIVATE TEST_QUIC)
    target_link_libraries(unit_tests PRIVATE quic_tests scion_quic pthread)
endif ()
