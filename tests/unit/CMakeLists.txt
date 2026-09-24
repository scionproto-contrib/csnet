set(DEPENDENCY_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/dependencies)

# Fetch cmocka (https://cmocka.org/), a unit testing framework for C.
ExternalProject_Add(
        cmocka
        GIT_REPOSITORY https://gitlab.com/cmocka/cmocka.git
        GIT_TAG cmocka-2.0.2
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${DEPENDENCY_INSTALL_DIR} -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DWITH_EXAMPLES=OFF
        BUILD_BYPRODUCTS ${DEPENDENCY_INSTALL_DIR}/lib/libcmocka.a
)

# Declare test executable
add_executable(unit_tests
        cmocka_main.c
        common/test_isd_as.c
        util/test_map.c
)
add_dependencies(unit_tests cmocka)

# Link SCION library and cmocka to tests
target_link_libraries(unit_tests PRIVATE scion ${DEPENDENCY_INSTALL_DIR}/lib/libcmocka.a)

# Give tests access to internal headers and to cmocka's
target_include_directories(unit_tests PRIVATE ${PROJECT_SOURCE_DIR}/lib ${DEPENDENCY_INSTALL_DIR}/include)

add_test(NAME unit_tests COMMAND unit_tests)
set_tests_properties(unit_tests PROPERTIES LABELS "unit")
