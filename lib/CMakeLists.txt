set(DEPENDENCY_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/dependencies)

# Fetch nghttp2
ExternalProject_Add(
        nghttp2
        GIT_REPOSITORY https://github.com/nghttp2/nghttp2.git
        GIT_TAG v1.65.0
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${DEPENDENCY_INSTALL_DIR} -DENABLE_LIB_ONLY=ON -DBUILD_STATIC_LIBS=ON
        BUILD_BYPRODUCTS ${DEPENDENCY_INSTALL_DIR}/lib/libnghttp2.a
)

# Fetch protobuf
ExternalProject_Add(
        protobuf
        GIT_REPOSITORY https://github.com/protocolbuffers/protobuf.git
        GIT_TAG v31.1
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${DEPENDENCY_INSTALL_DIR} -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_PROTOC_BINARIES=OFF -Dprotobuf_BUILD_LIBUPB=OFF -DABSL_PROPAGATE_CXX_STD=ON
)

# Fetch zlib
ExternalProject_Add(
        zlib
        GIT_REPOSITORY https://github.com/madler/zlib
        GIT_TAG v1.3.1
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${DEPENDENCY_INSTALL_DIR} -DZLIB_BUILD_EXAMPLES=OFF
        BUILD_BYPRODUCTS ${DEPENDENCY_INSTALL_DIR}/lib/libz.a
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

# Fetch curl
ExternalProject_Add(
        curl
        GIT_REPOSITORY https://github.com/curl/curl.git
        GIT_TAG curl-8_14_1
        CMAKE_ARGS
        -DCMAKE_INSTALL_PREFIX=${DEPENDENCY_INSTALL_DIR} -DHTTP_ONLY=ON -DBUILD_CURL_EXE=OFF -DBUILD_EXAMPLES=OFF
        -DBUILD_LIBCURL_DOCS=OFF -DBUILD_MISC_DOCS=OFF -DBUILD_TESTING=OFF -DBUILD_SHARED_LIBS=OFF
        -DBUILD_STATIC_LIBS=ON -DCURL_ENABLE_SSL=OFF -DUSE_NGHTTP2=OFF -DCURL_DISABLE_COOKIES=ON
        -DCURL_USE_LIBPSL=OFF -DCURL_ZLIB=OFF -DCURL_ZSTD=OFF -DCURL_BROTLI=OFF -DCURL_USE_LIBSSH2=OFF
        -DUSE_LIBIDN2=OFF
        BUILD_BYPRODUCTS ${DEPENDENCY_INSTALL_DIR}/lib/libcurl.a
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
        control_plane/policy.c
        control_plane/path_metadata.c
        control_plane/bootstrapper.c
        data_plane/packet.c
        data_plane/path.c
        data_plane/socket.c
        data_plane/udp.c
        data_plane/scmp.c
        data_plane/underlay.c
        util/http2_rpc.c
        util/list.c
        util/map.c
        proto/control_plane/experimental/v1/seg_detached_extensions.pb-c.c
        proto/control_plane/v1/seg.pb-c.c
        proto/control_plane/v1/seg_extensions.pb-c.c
        proto/crypto/v1/signed.pb-c.c
        google/protobuf/timestamp.pb-c.c
        error.c
)

add_dependencies(scion nghttp2)
add_dependencies(scion zlib)
add_dependencies(scion protobuf-c)
add_dependencies(scion curl)

# public headers
target_include_directories(scion PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
# internal headers
target_include_directories(scion PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
# dependency headers
target_include_directories(scion PRIVATE ${DEPENDENCY_INSTALL_DIR}/include)

# Link nghttp2
target_link_libraries(scion PRIVATE ${DEPENDENCY_INSTALL_DIR}/lib/libnghttp2.a)

# Link zlib
target_link_libraries(scion PRIVATE ${DEPENDENCY_INSTALL_DIR}/lib/libz.a)

# Link protobuf-c
target_link_libraries(scion PRIVATE ${DEPENDENCY_INSTALL_DIR}/lib/libprotobuf-c.a)

# Link libresolv
target_link_libraries(scion PRIVATE resolv)

# Link curl
target_link_libraries(scion PRIVATE ${DEPENDENCY_INSTALL_DIR}/lib/libcurl.a)

if (APPLE)
    # Link macOS frameworks required by curl
    target_link_libraries(scion PRIVATE "-framework CoreFoundation" "-framework SystemConfiguration")
endif ()

# Set compiler flags
extract_valid_c_compiler_flags(COMPILER_FLAGS
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
        -Wno-error=unused-command-line-argument
        -U_FORTIFY_SOURCE
        -D_FORTIFY_SOURCE=3
        -fstack-protector-strong
        -fno-delete-null-pointer-checks
        -fno-strict-overflow
        -fno-strict-aliasing
        -fstack-clash-protection
        -fcf-protection=full
        -Wtrampolines
        -Wbidi-chars=any
        -Wtrivial-auto-var-init
)
target_compile_options(scion PRIVATE ${COMPILER_FLAGS})

# Set linker flags
extract_valid_c_linker_flags(LINKER_FLAGS
        -Wl,-z,nodlopen
        -Wl,-z,noexecstack
        -Wl,-z,relro
        -Wl,-z,now
)
target_link_options(scion PRIVATE ${LINKER_FLAGS})

# enable additional flags in Release builds
if (CMAKE_BUILD_TYPE STREQUAL "Release")
    target_compile_options(scion PRIVATE -O2)
endif ()

# enable additional flags in Debug builds
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    extract_valid_c_linker_flags(SANITIZER_FLAGS
            -fsanitize=address
            -fno-omit-frame-pointer
            -fsanitize=undefined
            -fsanitize=leak
    )
    target_compile_options(scion PRIVATE -g -Werror ${SANITIZER_FLAGS})
    target_link_options(scion INTERFACE ${SANITIZER_FLAGS})
endif ()

# declare public headers for installation
set_target_properties(scion PROPERTIES PUBLIC_HEADER include/scion/scion.h)

# install library with public headers
install(TARGETS scion PUBLIC_HEADER DESTINATION include/scion)
# install the dependencies
install(FILES
        ${DEPENDENCY_INSTALL_DIR}/lib/libnghttp2.a
        ${DEPENDENCY_INSTALL_DIR}/lib/libz.a
        ${DEPENDENCY_INSTALL_DIR}/lib/libprotobuf-c.a
        ${DEPENDENCY_INSTALL_DIR}/lib/libcurl.a
        DESTINATION lib
)