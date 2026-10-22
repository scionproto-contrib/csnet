include(ExternalProject)

# Adds the external projects protobuf and protobuf-c (protoc, protoc-gen-c, libprotobuf-c.a). HOST_COMPILERS builds them
# with the host compilers, for cross-compiled projects.
#
#   scion_add_protobuf_tools(INSTALL_DIR <directory> [HOST_COMPILERS])
function(scion_add_protobuf_tools)
    cmake_parse_arguments(PARSE_ARGV 0 ARG "HOST_COMPILERS" "INSTALL_DIR" "")

    # Without this, AppleClang builds Abseil with C++14, which does not fit protobuf (C++17).
    set(cxx_args -DCMAKE_CXX_STANDARD=17 -DCMAKE_CXX_STANDARD_REQUIRED=ON)

    set(host_args)
    if (ARG_HOST_COMPILERS)
        find_program(HOST_C_COMPILER NAMES cc gcc clang REQUIRED)
        find_program(HOST_CXX_COMPILER NAMES c++ g++ clang++ REQUIRED)
        set(host_args -DCMAKE_TOOLCHAIN_FILE= -DCMAKE_C_COMPILER=${HOST_C_COMPILER}
                -DCMAKE_CXX_COMPILER=${HOST_CXX_COMPILER})
    endif ()

    # Fetch protobuf
    ExternalProject_Add(
            protobuf
            GIT_REPOSITORY https://github.com/protocolbuffers/protobuf.git
            GIT_TAG v31.1
            GIT_SHALLOW TRUE
            UPDATE_DISCONNECTED TRUE
            CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${ARG_INSTALL_DIR} -Dprotobuf_BUILD_TESTS=OFF -Dprotobuf_BUILD_PROTOC_BINARIES=ON -Dprotobuf_BUILD_LIBUPB=ON -Dprotobuf_WITH_ZLIB=OFF -DABSL_PROPAGATE_CXX_STD=ON ${cxx_args} ${host_args} ${DEPENDENCY_LAUNCHER_ARGS}
            BUILD_BYPRODUCTS ${ARG_INSTALL_DIR}/bin/protoc
    )

    # Fetch protobuf-c
    ExternalProject_Add(
            protobuf-c
            GIT_REPOSITORY https://github.com/protobuf-c/protobuf-c.git
            GIT_TAG v1.5.2
            GIT_SHALLOW TRUE
            UPDATE_DISCONNECTED TRUE
            SOURCE_SUBDIR build-cmake
            DEPENDS protobuf
            CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${ARG_INSTALL_DIR} -DCMAKE_PREFIX_PATH=${ARG_INSTALL_DIR} -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTS=OFF -DBUILD_PROTOC=ON ${cxx_args} ${host_args} ${DEPENDENCY_LAUNCHER_ARGS}
            BUILD_BYPRODUCTS ${ARG_INSTALL_DIR}/lib/libprotobuf-c.a ${ARG_INSTALL_DIR}/bin/protoc-gen-c
    )
endfunction()
