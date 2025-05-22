set(INCLUDES
        "."
        "../../lib"
        "../../lib/include"
)

set(SOURCES
        "main.c"

        "../../lib/google/protobuf/timestamp.pb-c.c"
        "../../lib/proto/control_plane/experimental/v1/seg_detached_extensions.pb-c.c"
        "../../lib/proto/control_plane/v1/seg_extensions.pb-c.c"
        "../../lib/proto/control_plane/v1/seg.pb-c.c"
        "../../lib/proto/crypto/v1/signed.pb-c.c"
        "../../lib/control_plane/segment.c"
        "../../lib/control_plane/graph.c"
        "../../lib/control_plane/fetch.c"
        "../../lib/control_plane/network.c"
        "../../lib/control_plane/policy.c"
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
        "../../lib/data_plane/socket.c"
        "../../lib/data_plane/udp.c"
        "../../lib/util/http2_rpc.c"
        "../../lib/util/list.c"
        "../../lib/util/map.c"
)

set(REQ
        protobuf-c
)

idf_component_register(SRCS ${SOURCES}
        INCLUDE_DIRS ${INCLUDES})

spiffs_create_partition_image(storage ../spiffs_partition FLASH_IN_PROJECT)
