# Generates C code from .proto files. The target writes <OUTPUT_DIR>/<proto path>.pb-c.c and .pb-c.h, and
# <target>_SOURCES lists the .c files. Users of them depend on the target and include OUTPUT_DIR.
#
#   scion_generate_proto(<target> PROTOC <protoc> PLUGIN <protoc-gen-c> ROOT <proto directory> OUTPUT_DIR <directory>
#           PROTOS <proto file relative to ROOT>... [DEPENDS <target>...])
function(scion_generate_proto TARGET)
    cmake_parse_arguments(PARSE_ARGV 1 ARG "" "PROTOC;PLUGIN;ROOT;OUTPUT_DIR" "PROTOS;DEPENDS")

    # A .proto file can import the others.
    set(proto_files)
    foreach (proto IN LISTS ARG_PROTOS)
        list(APPEND proto_files ${ARG_ROOT}/${proto})
    endforeach ()

    set(sources)
    foreach (proto IN LISTS ARG_PROTOS)
        string(REGEX REPLACE "\\.proto$" "" base ${proto})
        set(c_file ${ARG_OUTPUT_DIR}/${base}.pb-c.c)
        set(h_file ${ARG_OUTPUT_DIR}/${base}.pb-c.h)

        add_custom_command(
                OUTPUT ${c_file} ${h_file}
                COMMAND ${CMAKE_COMMAND} -E make_directory ${ARG_OUTPUT_DIR}
                COMMAND ${ARG_PROTOC} --plugin=protoc-gen-c=${ARG_PLUGIN} --c_out=${ARG_OUTPUT_DIR}
                -I ${ARG_ROOT} ${ARG_ROOT}/${proto}
                DEPENDS ${proto_files} ${ARG_PROTOC} ${ARG_PLUGIN} ${ARG_DEPENDS}
                COMMENT "Generating ${base}.pb-c.c"
                VERBATIM
        )
        list(APPEND sources ${c_file})
    endforeach ()

    add_custom_target(${TARGET} DEPENDS ${sources})
    set(${TARGET}_SOURCES ${sources} PARENT_SCOPE)
endfunction()
