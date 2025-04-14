set(test_list
        scion_test_list_create
        scion_test_list_append
        scion_test_list_append_all
        scion_test_list_append_all_null
        scion_test_list_pop
        scion_test_list_reverse
        scion_test_list_free
        scion_test_list_free_value
        scion_test_list_free_value_custom
        scion_test_ia_from_isd_as
        scion_test_ia_from_isd_as_too_large_as
        scion_test_get_isd
        scion_test_get_as
        scion_test_to_wildcard
        scion_test_is_wildcard
        scion_test_parse_ia
        scion_test_serialize_udp
        scion_test_serialize_meta_hdr
        scion_test_serialize_info_field
        scion_test_serialize_hop_field
        scion_test_serialize_path
        scion_test_serialize_scion_packet
        scion_test_serialize_scmp_echo
        scion_test_deserialize_udp
        scion_test_deserialize_meta_hdr
        scion_test_deserialize_info_field
        scion_test_deserialize_hop_field
        scion_test_deserialize_path
        scion_test_deserialize_scion_packet
        scion_test_init_raw_path
        scion_test_reverse_path
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
target_link_libraries(tests PUBLIC scion)

foreach (test ${test_list})
    add_test(NAME ${test} COMMAND tests ${test})
endforeach ()