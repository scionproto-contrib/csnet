// Copyright 2024 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#pragma once

#include <stdint.h>

#include "scion/common/isd_as.h"
#include "scion/data_plane/path.h"

#define SCION_LINE_LEN UINT8_C(4)
#define SCION_CMN_HDR_LEN UINT16_C(12)
#define SCION_MAX_HDR_LEN (UINT8_MAX * SCION_LINE_LEN)

// AddrType indicates the type of a host address in the SCION header.
// The AddrType consists of a sub-type and length part, both two bits wide.
// The four possible lengths are 4B (0), 8B (1), 12B (2), or 16B (3) bytes.
// There are four possible sub-types per address length.
// Documentation copied from:
// https://github.com/scionproto/scion/blob/a1ed6246ecd6beae9c82544032de4f9fecab1058/pkg/slayers/scion.go#L51
#define SCION_ADDR_TYPE_T4IP 0 // T = 0, L = 0
#define SCION_ADDR_TYPE_T16IP 3 // T = 0, L = 3

// Implementation of a SCION packet.
// Documentation copied from:
// https://github.com/scionproto/scion/blob/a1ed6246ecd6beae9c82544032de4f9fecab1058/pkg/slayers/scion.go#L90

struct scion_packet {
	// Common Header fields

	// version is version of the SCION Header. Currently, only 0 is supported.
	uint8_t version;

	// traffic_class denotes the traffic class. Its value in a received packet or fragment might be
	// different from the value sent by the packet’s source. The current use of the Traffic Class
	// field for Differentiated Services and Explicit Congestion Notification is specified in
	// RFC2474 and RFC3168
	uint8_t traffic_class;

	// flow_id is a 20-bit field used by a source to label sequences of packets to be treated in the
	// network as a single flow. It is mandatory to be set.
	uint32_t flow_id;

	// next_hdr  encodes the type of the first header after the SCION header. This can be either a
	// SCION extension or a layer-4 protocol such as TCP or UDP. Values of this field respect and
	// extend IANA’s assigned internet protocol numbers.
	uint8_t next_hdr;

	// payload_len is the length of the payload in bytes. The payload includes extension headers and
	// the L4 payload. This field is 16 bits long, supporting a maximum payload size of 64KB.
	uint16_t payload_len;

	// path_type specifies the type of path in this SCION header.
	uint8_t path_type;

	// dst_addr_type (4 bit) is the type/length of the destination address.
	uint8_t dst_addr_type;

	// src_addr_type (4 bit) is the type/length of the source address.
	uint8_t src_addr_type;

	// Address header fields.

	// dst_ia is the destination ISD-AS.
	scion_ia dst_ia;

	// src_ia is the source ISD-AS.
	scion_ia src_ia;

	// raw_dst_addr is the destination address.
	uint8_t *raw_dst_addr;
	uint8_t raw_dst_addr_length;

	// raw_src_addr is the source address.
	uint8_t *raw_src_addr;
	uint8_t raw_src_addr_length;

	// path is the path contained in the SCION header. It depends on the path_type field.
	struct scion_path *path;

	uint8_t *payload;
};

/*
 * FUNCTION: scion_packet_addr_type_len
 * -------------------
 * Returns the number of bytes required to represent a given raw address, depending on the type of the address.
 *
 * Arguments:
 *      - uint8_t addr_type: Integer representing the address type.
 *
 * Returns:
 *      - number of required bytes as uint16_t.
 */
uint8_t scion_packet_addr_type_len(uint8_t addr_type);

/*
 * FUNCTION: scion_packet_addr_hdr_len
 * -------------------
 * Returns the number of bytes required to represent the address header part of the SCION header of a given SCION
 * packet.
 *
 * Arguments:
 *      - struct scion_packet *packet: Pointer to the SCION packet.
 *
 * Returns:
 *      - number of required bytes as uint16_t.
 */
uint16_t scion_packet_addr_hdr_len(struct scion_packet *packet);

size_t scion_packet_len(struct scion_packet *packet);

/*
 * FUNCTION: scion_packet_free_internal
 * -------------------
 * Frees, if applicable, and set all internal values to 0 or NULL of a scion_packet struct, without freeing the struct
 * itself.
 *
 * Arguments:
 *      - struct scion_packet *packet: Pointer to the SCION packet.
 */
void scion_packet_free_internal(struct scion_packet *packet);

/*
 * FUNCTION: scion_packet_free
 * -------------------
 * Frees a scion_packet struct.
 *
 * Arguments:
 *      - struct scion_packet *packet: Pointer to the SCION packet.
 */
void scion_packet_free(struct scion_packet *packet);

/*
 * FUNCTION: scion_packet_serialize
 * -----------------
 * Serializes a scion packet into the provided buffer.
 *
 * Arguments:
 *      - struct scion_packet *packet: Pointer to the SCION packet which we want to serialize.
 *      - uint8_t *buf: Pointer to the buffer in which the serialized packet will be saved.
 *      - size_t *buf_len: Length of the provided buffer.
 *
 * Returns:
 *      - A integer status code:
 * 			if >= 0: the length of the serialized scion_packet struct.
 * 			if < an error code as defined in error.h.
 */
int scion_packet_serialize(struct scion_packet *packet, uint8_t *buf, size_t *buf_len);

/*
 * FUNCTION: scion_packet_deserialize
 * -------------------
 * Takes a buffer which contains a serialized SCION packet and deserializes it into a scion_packet struct.
 * IMPORTANT: the scion_packet struct need to be allocated before calling this function.
 *
 * Arguments:
 *      - uint8_t *buf: Pointer to the buffer.
 *      - size_t buf_len: length of the provided buffer.
 *      - struct scion_packet *packet: scion_packet struct into which the packet will be deserialized.
 *
 * Returns:
 *      - An integer status code, 0 for success or an error code as defined in error.h.
 */
int scion_packet_deserialize(uint8_t *buf, size_t buf_len, struct scion_packet *packet);
