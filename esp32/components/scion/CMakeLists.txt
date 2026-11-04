# Copyright 2026 ETH Zurich
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The csnet library (lib/) as an ESP-IDF component. Other projects can use it (and scion_quic) by adding this
# directory's parent to EXTRA_COMPONENT_DIRS.
set(CSNET_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..)
get_filename_component(CSNET_DIR ${CSNET_DIR} ABSOLUTE)
set(LIB ${CSNET_DIR}/lib)

set(SOURCES
        ${LIB}/control_plane/segment.c
        ${LIB}/control_plane/graph.c
        ${LIB}/control_plane/network.c
        ${LIB}/control_plane/policy.c
        ${LIB}/control_plane/path_collection.c
        ${LIB}/control_plane/path_metadata.c
        ${LIB}/control_plane/topology.c
        ${LIB}/common/isd_as.c
        ${LIB}/common/path_segment.c
        ${LIB}/common/as_entry.c
        ${LIB}/common/hop_field.c
        ${LIB}/common/info_field.c
        ${LIB}/common/path_collection.c
        ${LIB}/data_plane/scmp.c
        ${LIB}/data_plane/path.c
        ${LIB}/data_plane/packet.c
        ${LIB}/data_plane/underlay.c
        ${LIB}/data_plane/selector.c
        ${LIB}/data_plane/socket.c
        ${LIB}/data_plane/timestamp.c
        ${LIB}/data_plane/udp.c
        ${LIB}/error.c
        ${LIB}/util/addr.c
        ${LIB}/util/http2_rpc.c
        ${LIB}/util/list.c
        ${LIB}/util/map.c
)

idf_component_register(SRCS ${SOURCES}
        INCLUDE_DIRS ${LIB}/include
        PRIV_INCLUDE_DIRS ${LIB}
        REQUIRES protobuf-c lwip)

# Generate the C code of the .proto files with protoc and protoc-gen-c, built with the compilers of the host. This has
# to follow idf_component_register(), as the early expansion of the build system cannot run it.
include(${CSNET_DIR}/cmake/GenerateProto.cmake)
include(${CSNET_DIR}/cmake/ProtobufTools.cmake)

set(PROTO_TOOLS_DIR ${CMAKE_CURRENT_BINARY_DIR}/protobuf-tools)
scion_add_protobuf_tools(INSTALL_DIR ${PROTO_TOOLS_DIR} HOST_COMPILERS)

set(GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
scion_generate_proto(scion_proto
        PROTOC ${PROTO_TOOLS_DIR}/bin/protoc
        PLUGIN ${PROTO_TOOLS_DIR}/bin/protoc-gen-c
        ROOT ${CSNET_DIR}/proto
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
