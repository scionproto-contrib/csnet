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

# The QUIC client example needs the scion_quic library (-DBUILD_QUIC=ON)
if (BUILD_QUIC)
    add_executable(simple_quic_client simple_quic_client.c)
    target_link_libraries(simple_quic_client PRIVATE scion_quic m)
endif ()
