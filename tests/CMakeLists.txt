set(test_list
        list_create
        list_append
        list_append_all
        list_append_all_null
        list_pop
        list_reverse
        list_free
        list_free_value
        list_free_value_custom
        ia_from_isd_as
        ia_from_isd_as_too_large_as
        get_isd
        get_as
        to_wildcard
        is_wildcard
        parse_ia
        serialize_udp
        serialize_meta_hdr
        serialize_info_field
        serialize_hop_field
        serialize_path
        serialize_scion_packet
        serialize_scmp_echo
        deserialize_udp
        deserialize_meta_hdr
        deserialize_info_field
        deserialize_hop_field
        deserialize_path
        deserialize_scion_packet
        init_raw_path
        reverse_path
)

# Declare test executable
add_executable(tests
        testing.c
        common/test_isd_as.c
        data_plane/test_deserialization.c
        data_plane/test_path.c
        data_plane/test_serialization.c
        util/test_linked_list.c
)

# Link SCION library to tests
target_link_libraries(tests PRIVATE scion)

# Give tests access to internal headers
target_include_directories(tests PRIVATE ${PROJECT_SOURCE_DIR}/lib)

# Register all tests in the list
foreach (test ${test_list})
    add_test(NAME ${test} COMMAND tests ${test})
    set_tests_properties(${test} PROPERTIES LABELS "unit")
endforeach ()