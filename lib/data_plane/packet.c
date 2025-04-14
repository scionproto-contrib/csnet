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

#include <stdint.h>
#include <stdlib.h>

#include "scion/data_plane/packet.h"

#include "scion/error.h"

#include <assert.h>
#include <string.h>

uint8_t scion_packet_addr_type_len(uint8_t addr_type)
{
	return (uint8_t)(SCION_LINE_LEN * (1 + (addr_type & 0x3)));
}

uint16_t scion_packet_addr_hdr_len(struct scion_packet *packet)
{
	return (uint16_t)(2 * SCION_IA_BYTES + scion_packet_addr_type_len(packet->dst_addr_type)
					  + scion_packet_addr_type_len(packet->src_addr_type));
}

uint16_t scion_packet_path_hdr_len(struct scion_packet *packet)
{
	if (packet->path_type == SCION_PATH_TYPE_EMPTY) {
		return 0;
	}

	return packet->path->raw_path->length;
}

uint16_t scion_packet_hdr_len(struct scion_packet *packet)
{
	return (uint16_t)(SCION_CMN_HDR_LEN + scion_packet_addr_hdr_len(packet) + scion_packet_path_hdr_len(packet));
}

size_t scion_packet_len(struct scion_packet *packet)
{
	return scion_packet_hdr_len(packet) + packet->payload_len;
}

void scion_packet_free_internal(struct scion_packet *packet)
{
	if (packet == NULL) {
		return;
	}

	if (packet->raw_dst_addr != NULL) {
		free(packet->raw_dst_addr);
		packet->raw_dst_addr = NULL;
	}

	if (packet->raw_src_addr != NULL) {
		free(packet->raw_src_addr);
		packet->raw_src_addr = NULL;
	}

	if (packet->path != NULL) {
		scion_path_free(packet->path);
		packet->path = NULL;
	}

	if (packet->payload != NULL) {
		free(packet->payload);
		packet->payload = NULL;
	}
}

void scion_packet_free(struct scion_packet *packet)
{
	if (packet == NULL) {
		return;
	}
	scion_packet_free_internal(packet);
	free(packet);
}

/*
 * ##################################################################
 * #################### Serialize SCION Packet ######################
 * ##################################################################
 */

int scion_packet_serialize(struct scion_packet *packet, uint8_t *buf, size_t *buf_len)
{
	assert(packet);
	assert(buf);

	(void)memset(buf, 0, *buf_len);

	uint16_t path_length = scion_packet_path_hdr_len(packet);
	uint16_t total_hdr_len = scion_packet_hdr_len(packet);

	if (total_hdr_len > SCION_MAX_HDR_LEN) {
		return SCION_MAX_HDR_LEN_EXCEEDED;
	}

	// header must be a multiple of line length. (i.e. header has to be 4 bytes aligned)
	assert(total_hdr_len % SCION_LINE_LEN == 0);

	size_t total_len = scion_packet_len(packet);

	if (total_len > *buf_len) {
		// buffer is not big enough.
		return SCION_BUFFER_SIZE_ERR;
	}

	*buf_len = total_len;

	// Common Header
	uint32_t first_line = ((uint32_t)packet->version) << 28 | ((uint32_t)packet->traffic_class) << 20
						  | (packet->flow_id & 0xfffff);
	*(uint32_t *)buf = htobe32(first_line);

	buf[4] = (uint8_t)packet->next_hdr;
	// hdr_len is the length of the SCION header in multiples of 4 bytes. The SCION header length is
	// computed as hdr_len * 4 bytes.
	buf[5] = (uint8_t)(total_hdr_len / 4);

	*(uint16_t *)(buf + 6) = htobe16(packet->payload_len);

	buf[8] = (uint8_t)packet->path_type;
	buf[9] = (uint8_t)(packet->dst_addr_type << 4 | packet->src_addr_type);
	*(uint16_t *)(buf + 10) = htobe16(0);

	// Addr Header
	uint16_t offset = SCION_CMN_HDR_LEN;
	uint64_t dst_ia_n = htobe64((uint64_t)packet->dst_ia);
	(void)memcpy(buf + offset, &dst_ia_n, sizeof(dst_ia_n));
	offset += SCION_IA_BYTES;
	uint64_t src_ia_n = htobe64((uint64_t)packet->src_ia);
	(void)memcpy(buf + offset, &src_ia_n, sizeof(src_ia_n));
	offset += SCION_IA_BYTES;

	uint16_t dst_addr_bytes = scion_packet_addr_type_len(packet->dst_addr_type);
	if (dst_addr_bytes != (uint16_t)packet->raw_dst_addr_length) {
		// length mismatch on raw destination address
		return SCION_LEN_MISMATCH;
	}
	(void)memcpy(buf + offset, packet->raw_dst_addr, dst_addr_bytes);
	offset += dst_addr_bytes;

	uint16_t src_addr_bytes = scion_packet_addr_type_len(packet->src_addr_type);
	if (src_addr_bytes != (uint16_t)packet->raw_src_addr_length) {
		// length mismatch on raw source address
		return SCION_LEN_MISMATCH;
	}
	(void)memcpy(buf + offset, packet->raw_src_addr, src_addr_bytes);
	offset += src_addr_bytes; // COMMENT: this line varies from the go implementation, could be source of problem?

	// Copy Path
	if (path_length > 0) {
		(void)memcpy(buf + offset, packet->path->raw_path->raw, path_length);
		offset += path_length;
	}

	// Copy payload
	if (packet->payload_len > 0) {
		(void)memcpy(buf + offset, packet->payload, packet->payload_len);
	}
	return 0;
}

// scion_deserialize_addr_hdr decodes the destination and source ISD-AS-Host address triples from the provided
// buffer. The caller must ensure that the correct address types and lengths are set in the SCION
// layer, otherwise the results of this method are undefined.
// Comment taken from:
// https://github.com/scionproto/scion/blob/a1ed6246ecd6beae9c82544032de4f9fecab1058/pkg/slayers/scion.go#L199
static int scion_deserialize_addr_hdr(uint8_t *buf, size_t buf_len, struct scion_packet *packet)
{
	assert(packet);
	assert(buf);

	if (buf_len < scion_packet_addr_hdr_len(packet)) {
		return SCION_BUFFER_SIZE_ERR;
	}

	(void)memcpy(&packet->dst_ia, buf, sizeof(uint64_t));
	packet->dst_ia = be64toh(packet->dst_ia);
	uint16_t offset = SCION_IA_BYTES;

	(void)memcpy(&packet->src_ia, buf + offset, sizeof(uint64_t));
	packet->src_ia = be64toh(packet->src_ia);
	offset += SCION_IA_BYTES;

	packet->raw_dst_addr_length = scion_packet_addr_type_len(packet->dst_addr_type);
	packet->raw_dst_addr = (uint8_t *)malloc(packet->raw_dst_addr_length);
	(void)memcpy(packet->raw_dst_addr, buf + offset, packet->raw_dst_addr_length);
	offset += packet->raw_dst_addr_length;

	packet->raw_src_addr_length = scion_packet_addr_type_len(packet->src_addr_type);
	packet->raw_src_addr = (uint8_t *)malloc(packet->raw_src_addr_length);
	(void)memcpy(packet->raw_src_addr, buf + offset, packet->raw_src_addr_length);

	return 0;
}

int scion_packet_deserialize(uint8_t *buf, size_t buf_len, struct scion_packet *packet)
{
	assert(packet);
	assert(buf);
	int ret;

	if (buf_len < SCION_CMN_HDR_LEN) {
		// Packet shorter than common header, i.e. incomplete packet
		return SCION_NOT_ENOUGH_DATA;
	}

	uint32_t firstline = be32toh(*(uint32_t *)buf);

	packet->version = (uint8_t)(firstline >> 28 & 0xff);
	packet->traffic_class = (uint8_t)(firstline >> 20 & 0xff);
	packet->flow_id = firstline & 0xfffff;
	packet->next_hdr = buf[4];
	packet->payload_len = be16toh(*(uint16_t *)(buf + 6));
	packet->path_type = buf[8];
	packet->dst_addr_type = buf[9] >> 4 & 0xf;
	packet->src_addr_type = buf[9] & 0xf;

	ret = scion_deserialize_addr_hdr(buf + SCION_CMN_HDR_LEN, buf_len - SCION_CMN_HDR_LEN, packet);
	if (ret != 0) {
		return ret;
	}

	uint16_t addr_hdr_len = scion_packet_addr_hdr_len(packet);
	uint16_t current_offset = SCION_CMN_HDR_LEN + addr_hdr_len;
	uint16_t hdr_bytes = buf[5] * SCION_LINE_LEN;
	uint16_t hdr_bytes_without_path = SCION_CMN_HDR_LEN + addr_hdr_len;

	if (hdr_bytes_without_path > hdr_bytes) {
		// packet hdr_len invalid
		return SCION_INVALID_FIELD;
	}

	uint16_t path_hdr_len = hdr_bytes - hdr_bytes_without_path;

	if ((size_t)(current_offset + path_hdr_len + packet->payload_len) > buf_len) {
		// missing part of the payload
		return SCION_NOT_ENOUGH_DATA;
	}

	// TODO: move this logic to path.c
	packet->path = malloc(sizeof(*packet->path));
	if (packet->path == NULL) {
		return SCION_MALLOC_FAIL;
	}
	packet->path->dst = packet->dst_ia;
	packet->path->src = packet->src_ia;
	packet->path->path_type = packet->path_type;
	// TODO: metadata calculation
	packet->path->metadata = NULL;
	// TODO: correct weight calculation?
	packet->path->weight = 0;
	if (packet->path->path_type == SCION_PATH_TYPE_EMPTY) {
		packet->path->raw_path = NULL;
	} else {
		packet->path->raw_path = malloc(sizeof(*packet->path->raw_path));
		if (packet->path->raw_path == NULL) {
			ret = SCION_MALLOC_FAIL;
			goto cleanup_path;
		}
		packet->path->raw_path->length = path_hdr_len;
		packet->path->raw_path->raw = (uint8_t *)malloc(path_hdr_len);
		(void)memcpy(packet->path->raw_path->raw, buf + current_offset, path_hdr_len);
		current_offset += path_hdr_len;
	}

	packet->payload = (uint8_t *)malloc(packet->payload_len);
	if (packet->payload == NULL) {
		ret = SCION_MALLOC_FAIL;
		goto cleanup_raw_path;
	}
	(void)memcpy(packet->payload, buf + current_offset, packet->payload_len);

exit:
	return ret;

cleanup_raw_path:
	free(packet->path->raw_path);

cleanup_path:
	free(packet->path);

	goto exit;
}
