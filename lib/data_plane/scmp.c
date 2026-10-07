// Copyright 2025 ETH Zurich
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

#include <assert.h>
#include <memory.h>
#include <stdio.h>
#include <stdlib.h>

#include "data_plane/scmp.h"
#include "util/endian.h"

enum scion_scmp_type scion_scmp_get_type(const uint8_t *buf, uint16_t buf_len)
{
	if (buf_len < 1) {
		return 0;
	}

	return buf[0];
}

uint8_t scion_scmp_get_code(const uint8_t *buf, uint16_t buf_len)
{
	if (buf_len < 2) {
		return 0;
	}

	return buf[1];
}

bool scion_scmp_is_error(const uint8_t *buf, uint16_t buf_len)
{
	return scion_scmp_get_type(buf, buf_len) >> 7 == 0;
}

// #######  Echo messages  #######

uint16_t scion_scmp_echo_len(struct scion_scmp_echo *scmp_echo)
{
	assert(scmp_echo);
	return SCION_SCMP_ECHO_HDR_LEN + scmp_echo->data_length;
}

int scion_scmp_echo_deserialize(const uint8_t *buf, uint16_t buf_len, struct scion_scmp_echo *scmp_echo)
{
	assert(scmp_echo);
	assert(buf);

	if (buf_len < SCION_SCMP_ECHO_HDR_LEN) {
		return SCION_ERR_BUF_TOO_SMALL;
	}

	enum scion_scmp_type type = scion_scmp_get_type(buf, buf_len);
	if (type != SCION_SCMP_TYPE_ECHO_REQUEST && type != SCION_SCMP_TYPE_ECHO_REPLY) {
		return SCION_ERR_PACKET_FIELD_INVALID;
	}

	if (buf[1] != 0) {
		return SCION_ERR_SCMP_CODE_INVALID;
	}

	uint16_t data_len = buf_len - SCION_SCMP_ECHO_HDR_LEN;
	scmp_echo->data_length = data_len;

	if (scmp_echo->data_length > 0) {
		scmp_echo->data = malloc(data_len);
		if (scmp_echo->data == NULL) {
			return SCION_ERR_MEM_ALLOC_FAIL;
		}
	} else {
		scmp_echo->data = NULL;
	}

	scmp_echo->type = type;
	scmp_echo->id = scion_load_be16(buf + 4);
	scmp_echo->seqno = scion_load_be16(buf + 6);

	if (data_len > 0) {
		(void)memcpy(scmp_echo->data, buf + 8, data_len);
	}

	return 0;
}

int scion_scmp_echo_serialize(const struct scion_scmp_echo *scmp_echo, uint8_t *buf, uint16_t buf_len)
{
	assert(scmp_echo);
	assert(buf);

	if (buf_len < SCION_SCMP_ECHO_HDR_LEN + scmp_echo->data_length) {
		return SCION_ERR_BUF_TOO_SMALL;
	}

	*(buf) = (uint8_t)scmp_echo->type;
	*(buf + 1) = 0;
	scion_store_be16(buf + 2, 0); // TODO checksum
	scion_store_be16(buf + 4, scmp_echo->id);
	scion_store_be16(buf + 6, scmp_echo->seqno);

	if (scmp_echo->data_length > 0) {
		(void)memcpy(buf + SCION_SCMP_ECHO_HDR_LEN, scmp_echo->data, scmp_echo->data_length);
	}

	return 0;
}

void scion_scmp_echo_free_members(struct scion_scmp_echo *scmp_echo)
{
	free(scmp_echo->data);
	scmp_echo->data = NULL;
}

// #######  Error messages  #######

// Returns the size of the type specific information that follows the SCMP header, or -1 for an unknown type.
static int error_info_len(enum scion_scmp_type type)
{
	switch (type) {
	case SCION_SCMP_TYPE_DESTINATION_UNREACHABLE:
	case SCION_SCMP_TYPE_PACKET_TOO_BIG:
	case SCION_SCMP_TYPE_PARAMETER_PROBLEM:
		return 4;
	case SCION_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN:
		// ISD-AS and interface
		return 16;
	case SCION_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN:
		// ISD-AS, ingress interface and egress interface
		return 24;
	case SCION_SCMP_TYPE_ECHO_REQUEST:
	case SCION_SCMP_TYPE_ECHO_REPLY:
		return -1;
	}

	return -1;
}

size_t scion_scmp_error_len(const struct scion_scmp_error *scmp_error)
{
	assert(scmp_error);

	int info_len = error_info_len(scmp_error->type);
	if (info_len < 0) {
		return 0;
	}

	return SCION_SCMP_HDR_LEN + (size_t)info_len + scmp_error->packet_length;
}

int scion_scmp_error_serialize(const struct scion_scmp_error *scmp_error, uint8_t *buf, size_t buf_len)
{
	assert(scmp_error);
	assert(buf);
	assert(scmp_error->packet_length == 0 || scmp_error->packet);

	int info_len = error_info_len(scmp_error->type);
	if (info_len < 0) {
		return SCION_ERR_PACKET_FIELD_INVALID;
	}

	size_t len = scion_scmp_error_len(scmp_error);
	if (buf_len < len) {
		return SCION_ERR_BUF_TOO_SMALL;
	}

	buf[0] = (uint8_t)scmp_error->type;
	buf[1] = scmp_error->code;
	scion_store_be16(buf + 2, 0); // TODO checksum

	uint8_t *info = buf + SCION_SCMP_HDR_LEN;
	switch (scmp_error->type) {
	case SCION_SCMP_TYPE_DESTINATION_UNREACHABLE:
		(void)memset(info, 0, 4);
		break;
	case SCION_SCMP_TYPE_PACKET_TOO_BIG:
		scion_store_be16(info, 0);
		scion_store_be16(info + 2, scmp_error->info.packet_too_big.mtu);
		break;
	case SCION_SCMP_TYPE_PARAMETER_PROBLEM:
		scion_store_be16(info, 0);
		scion_store_be16(info + 2, scmp_error->info.parameter_problem.pointer);
		break;
	case SCION_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN:
		scion_store_be64(info, scmp_error->info.external_interface_down.ia);
		scion_store_be64(info + 8, scmp_error->info.external_interface_down.interface);
		break;
	case SCION_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN:
		scion_store_be64(info, scmp_error->info.internal_connectivity_down.ia);
		scion_store_be64(info + 8, scmp_error->info.internal_connectivity_down.ingress_interface);
		scion_store_be64(info + 16, scmp_error->info.internal_connectivity_down.egress_interface);
		break;
	default:
		// error_info_len() has rejected the types that are not errors
		break;
	}

	if (scmp_error->packet_length > 0) {
		(void)memcpy(info + info_len, scmp_error->packet, scmp_error->packet_length);
	}

	return 0;
}

int scion_scmp_error_deserialize(const uint8_t *buf, size_t buf_len, struct scion_scmp_error *scmp_error)
{
	assert(buf || buf_len == 0);
	assert(scmp_error);

	if (buf_len < SCION_SCMP_HDR_LEN) {
		return SCION_ERR_BUF_TOO_SMALL;
	}

	enum scion_scmp_type type = (enum scion_scmp_type)buf[0];
	int info_len = error_info_len(type);
	if (info_len < 0) {
		return SCION_ERR_PACKET_FIELD_INVALID;
	}

	size_t header_len = SCION_SCMP_HDR_LEN + (size_t)info_len;
	if (buf_len < header_len) {
		return SCION_ERR_BUF_TOO_SMALL;
	}

	size_t packet_length = buf_len - header_len;
	if (packet_length > UINT16_MAX) {
		return SCION_ERR_MSG_TOO_LARGE;
	}

	*scmp_error = (struct scion_scmp_error){ .type = type, .code = buf[1] };

	const uint8_t *info = buf + SCION_SCMP_HDR_LEN;
	switch (type) {
	case SCION_SCMP_TYPE_DESTINATION_UNREACHABLE:
		break;
	case SCION_SCMP_TYPE_PACKET_TOO_BIG:
		scmp_error->info.packet_too_big.mtu = scion_load_be16(info + 2);
		break;
	case SCION_SCMP_TYPE_PARAMETER_PROBLEM:
		scmp_error->info.parameter_problem.pointer = scion_load_be16(info + 2);
		break;
	case SCION_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN:
		scmp_error->info.external_interface_down.ia = scion_load_be64(info);
		scmp_error->info.external_interface_down.interface = scion_load_be64(info + 8);
		break;
	case SCION_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN:
		scmp_error->info.internal_connectivity_down.ia = scion_load_be64(info);
		scmp_error->info.internal_connectivity_down.ingress_interface = scion_load_be64(info + 8);
		scmp_error->info.internal_connectivity_down.egress_interface = scion_load_be64(info + 16);
		break;
	default:
		// error_info_len() has rejected the types that are not errors
		break;
	}

	if (packet_length > 0) {
		scmp_error->packet = malloc(packet_length);
		if (scmp_error->packet == NULL) {
			return SCION_ERR_MEM_ALLOC_FAIL;
		}
		(void)memcpy(scmp_error->packet, info + info_len, packet_length);
		scmp_error->packet_length = (uint16_t)packet_length;
	}

	return 0;
}

void scion_scmp_error_free_members(struct scion_scmp_error *scmp_error)
{
	assert(scmp_error);

	free(scmp_error->packet);
	scmp_error->packet = NULL;
	scmp_error->packet_length = 0;
}
