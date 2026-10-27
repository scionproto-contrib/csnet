set(INCLUDES
        "."
        "../../lib"
        "../../lib/include"
)

set(SOURCES
        "main.c"

        "../../lib/control_plane/segment.c"
        "../../lib/control_plane/graph.c"
        "../../lib/control_plane/network.c"
        "../../lib/control_plane/policy.c"
        "../../lib/control_plane/path_collection.c"
        "../../lib/control_plane/path_metadata.c"
        "../../lib/control_plane/topology.c"
        "../../lib/common/isd_as.c"
        "../../lib/common/path_segment.c"
        "../../lib/common/as_entry.c"
        "../../lib/common/hop_field.c"
        "../../lib/common/info_field.c"
        "../../lib/common/path_collection.c"
        "../../lib/data_plane/scmp.c"
        "../../lib/data_plane/path.c"
        "../../lib/data_plane/packet.c"
        "../../lib/data_plane/underlay.c"
        "../../lib/data_plane/selector.c"
        "../../lib/data_plane/socket.c"
        "../../lib/data_plane/timestamp.c"
        "../../lib/data_plane/udp.c"
        "../../lib/error.c"
        "../../lib/util/addr.c"
        "../../lib/util/http2_rpc.c"
        "../../lib/util/list.c"
        "../../lib/util/map.c"
)

set(REQ
        protobuf-c
)

idf_component_register(SRCS ${SOURCES}
        INCLUDE_DIRS ${INCLUDES})

# Generate the C code of the .proto files with protoc and protoc-gen-c, built with the compilers of the host. This has
# to follow idf_component_register(), as the early expansion of the build system cannot run it.
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/GenerateProto.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/../../cmake/ProtobufTools.cmake)

set(PROTO_TOOLS_DIR ${CMAKE_CURRENT_BINARY_DIR}/protobuf-tools)
scion_add_protobuf_tools(INSTALL_DIR ${PROTO_TOOLS_DIR} HOST_COMPILERS)

set(GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
scion_generate_proto(scion_proto
        PROTOC ${PROTO_TOOLS_DIR}/bin/protoc
        PLUGIN ${PROTO_TOOLS_DIR}/bin/protoc-gen-c
        ROOT ${CMAKE_CURRENT_LIST_DIR}/../../proto
        OUTPUT_DIR ${GENERATED_DIR}
        PROTOS
        google/protobuf/timestamp.proto
        proto/crypto/v1/signed.proto
        proto/control_plane/experimental/v1/seg_detached_extensions.proto
        proto/control_plane/v1/seg_extensions.proto
        proto/control_plane/v1/seg.proto
        DEPENDS protobuf protobuf-c
)

target_sources(${COMPONENT_LIB} PRIVATE ${scion_proto_SOURCES})
target_include_directories(${COMPONENT_LIB} PRIVATE ${GENERATED_DIR})
add_dependencies(${COMPONENT_LIB} scion_proto)

spiffs_create_partition_image(storage ../spiffs_partition FLASH_IN_PROJECT)
