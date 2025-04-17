set(DEPENDENCY_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/dependencies)

# Fetch nghttp2
ExternalProject_Add(
        nghttp2
        GIT_REPOSITORY https://github.com/nghttp2/nghttp2.git
        GIT_TAG v1.65.0
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${DEPENDENCY_INSTALL_DIR} -DENABLE_LIB_ONLY=ON -DBUILD_STATIC_LIBS=ON
        BUILD_BYPRODUCTS ${DEPENDENCY_INSTALL_DIR}/lib/libnghttp2.so
)

# Fetch protobuf
ExternalProject_Add(
        protobuf
        GIT_REPOSITORY https://github.com/protocolbuffers/protobuf.git
        GIT_TAG v29.3
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${DEPENDENCY_INSTALL_DIR} -Dprotobuf_BUILD_TESTS=OFF -DABSL_PROPAGATE_CXX_STD=ON
)

# Fetch protobuf-c
ExternalProject_Add(
        protobuf-c
        GIT_REPOSITORY https://github.com/protobuf-c/protobuf-c.git
        GIT_TAG v1.5.1
        SOURCE_SUBDIR build-cmake
        DEPENDS protobuf
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${DEPENDENCY_INSTALL_DIR} -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTS=OFF -DBUILD_PROTOC=OFF
        BUILD_BYPRODUCTS ${DEPENDENCY_INSTALL_DIR}/lib/libprotobuf-c.a
)

# Declare library
add_library(scion STATIC
        common/as_entry.c
        common/info_field.c
        common/hop_field.c
        common/isd_as.c
        common/path_segment.c
        common/path_collection.c
        control_plane/fetch.c
        control_plane/graph.c
        control_plane/segment.c
        control_plane/topology.c
        control_plane/network.c
        data_plane/packet.c
        data_plane/path.c
        data_plane/ping.c
        data_plane/socket.c
        data_plane/udp.c
        data_plane/scmp.c
        util/http2_rpc.c
        util/linked_list.c
        proto/control_plane/experimental/v1/seg_detached_extensions.pb-c.c
        proto/control_plane/v1/seg.pb-c.c
        proto/control_plane/v1/seg_extensions.pb-c.c
        proto/crypto/v1/signed.pb-c.c
        google/protobuf/timestamp.pb-c.c
        error.c
)

add_dependencies(scion nghttp2)
add_dependencies(scion protobuf-c)

# Add scion includes
target_include_directories(scion PUBLIC ../include)
target_include_directories(scion PRIVATE ${DEPENDENCY_INSTALL_DIR}/include)

# Link nghttp2
target_link_libraries(scion PRIVATE ${DEPENDENCY_INSTALL_DIR}/lib/libnghttp2.so)

# Link protobuf-c
target_link_libraries(scion PRIVATE ${DEPENDENCY_INSTALL_DIR}/lib/libprotobuf-c.a)

# Set compile options
target_compile_options(scion PRIVATE
        -O2
        -Wall
        -Wextra
        -Wformat
        -Wformat=2
        -Wconversion
        -Wsign-conversion
        -Wimplicit-fallthrough
        -Werror=format-security
        -Werror=implicit
        -Werror=incompatible-pointer-types
        -Werror=int-conversion
        $<$<CONFIG:Debug>:-Werror>
        -U_FORTIFY_SOURCE
        -D_FORTIFY_SOURCE=3
        -fstack-clash-protection
        -fstack-protector-strong
        -fcf-protection=full
        -fno-delete-null-pointer-checks
        -fno-strict-overflow
        -fno-strict-aliasing
        $<$<CONFIG:Debug>:-fsanitize=address -fno-omit-frame-pointer>
        $<$<CONFIG:Debug>:-fsanitize=leak>
        $<$<CONFIG:Debug>:-fsanitize=undefined>
)

target_link_options(scion PRIVATE
        -Wl,-z,nodlopen
        -Wl,-z,noexecstack
        -Wl,-z,relro
        -Wl,-z,now
)

target_link_options(scion INTERFACE
        $<$<CONFIG:Debug>:-fsanitize=address -fno-omit-frame-pointer>
        $<$<CONFIG:Debug>:-fsanitize=leak>
        $<$<CONFIG:Debug>:-fsanitize=undefined>
)

# enable GCC specific flags
if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
    target_compile_options(scion PRIVATE
            -Wtrampolines
            -Wbidi-chars=any
            -Wtrivial-auto-var-init
    )
endif ()