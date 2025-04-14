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