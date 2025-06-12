# Configure scripts
configure_file(start_network_and_hosts.sh ./start_network_and_hosts.sh @ONLY)
configure_file(stop_network_and_hosts.sh ./stop_network_and_hosts.sh @ONLY)

# Start network and hosts
add_test(NAME start_network_and_hosts COMMAND ./start_network_and_hosts.sh)
set_tests_properties(start_network_and_hosts PROPERTIES
        FIXTURES_SETUP network_and_hosts_fixture
)

# Stop network and hosts
add_test(NAME stop_network_and_hosts COMMAND ./stop_network_and_hosts.sh)
set_tests_properties(stop_network_and_hosts PROPERTIES
        FIXTURES_CLEANUP network_and_hosts_fixture
)

set(test_list
        send_udp
        choose_path
        server_with_multiple_clients
        custom_policy
)

# Register all tests in the list
foreach (test ${test_list})
    add_executable(test_e2e_${test} ${test}.c)
    target_link_libraries(test_e2e_${test} PRIVATE scion)
    add_test(NAME ${test} COMMAND test_e2e_${test})
    set_tests_properties(${test} PROPERTIES
            FIXTURES_REQUIRED network_and_hosts_fixture
            LABELS "e2e"
            ENVIRONMENT "TOPO_BASE_PATH=${CMAKE_SOURCE_DIR}/network/scion-testnet/topos/default"
    )
endforeach ()