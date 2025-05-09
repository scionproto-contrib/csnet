add_executable(ping ping.c)
target_link_libraries(ping PRIVATE scion)

# tests
add_test(NAME ping_different_as COMMAND ping -c 3 2-ff00:0:222,fd00:f00d:cafe::7f00:55 ../topology/topology.json)
set_tests_properties(ping_different_as PROPERTIES LABELS "e2e")

add_test(NAME ping_same_as COMMAND ping -c 3 1-ff00:0:133,127.0.0.100 ../topology/topology.json)
set_tests_properties(ping_same_as PROPERTIES LABELS "e2e")

# install ping binary
install(TARGETS ping)