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
#include <inttypes.h>
#include <memory.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

const char *scion_scmp_type_str(enum scion_scmp_type type)
{
	switch (type) {
	case SCION_SCMP_TYPE_DESTINATION_UNREACHABLE:
		return "destination unreachable";
	case SCION_SCMP_TYPE_PACKET_TOO_BIG:
		return "packet too big";
	case SCION_SCMP_TYPE_PARAMETER_PROBLEM:
		return "parameter problem";
	case SCION_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN:
		return "external interface down";
	case SCION_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN:
		return "internal connectivity down";
	case SCION_SCMP_TYPE_ECHO_REQUEST:
		return "echo request";
	case SCION_SCMP_TYPE_ECHO_REPLY:
		return "echo reply";
	case SCION_SCMP_TYPE_TRACEROUTE_REQUEST:
		return "traceroute request";
	case SCION_SCMP_TYPE_TRACEROUTE_REPLY:
		return "traceroute reply";
	}

	return "unknown";
}

static const char *destination_unreachable_code_str(enum scion_scmp_code_destination_unreachable code)
{
	switch (code) {
	case SCION_SCMP_CODE_DESTINATION_UNREACHABLE_NO_ROUTE:
		return "no route to destination";
	case SCION_SCMP_CODE_DESTINATION_UNREACHABLE_ADMINISTRATIVELY_DENIED:
		return "communication administratively denied";
	case SCION_SCMP_CODE_DESTINATION_UNREACHABLE_BEYOND_SCOPE:
		return "beyond scope of source address";
	case SCION_SCMP_CODE_DESTINATION_UNREACHABLE_ADDRESS_UNREACHABLE:
		return "address unreachable";
	case SCION_SCMP_CODE_DESTINATION_UNREACHABLE_PORT_UNREACHABLE:
		return "port unreachable";
	case SCION_SCMP_CODE_DESTINATION_UNREACHABLE_SOURCE_ADDRESS_FAILED_POLICY:
		return "source address failed ingress/egress policy";
	case SCION_SCMP_CODE_DESTINATION_UNREACHABLE_REJECT_ROUTE:
		return "reject route to destination";
	}

	return "unknown";
}

static const char *parameter_problem_code_str(enum scion_scmp_code_parameter_problem code)
{
	switch (code) {
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_ERRONEOUS_HEADER_FIELD:
		return "erroneous header field";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_NEXT_HEADER:
		return "unknown next header type";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_COMMON_HEADER:
		return "invalid common header";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_VERSION:
		return "unknown SCION version";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_FLOW_ID_REQUIRED:
		return "flow ID required";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_PACKET_SIZE:
		return "invalid packet size";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_PATH_TYPE:
		return "unknown path type";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_ADDRESS_FORMAT:
		return "unknown address format";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_ADDRESS_HEADER:
		return "invalid address header";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_SOURCE_ADDRESS:
		return "invalid source address";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_DESTINATION_ADDRESS:
		return "invalid destination address";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_NON_LOCAL_DELIVERY:
		return "non-local delivery";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_PATH:
		return "invalid path";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_HOP_FIELD_INGRESS:
		return "unknown hop field ingress interface";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_HOP_FIELD_EGRESS:
		return "unknown hop field egress interface";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_HOP_FIELD_MAC:
		return "invalid hop field MAC";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_PATH_EXPIRED:
		return "path expired";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_SEGMENT_CHANGE:
		return "invalid segment change";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_EXTENSION_HEADER:
		return "invalid extension header";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_HOP_BY_HOP_OPTION:
		return "unknown hop-by-hop option";
	case SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_END_TO_END_OPTION:
		return "unknown end-to-end option";
	}

	return "unknown";
}

const char *scion_scmp_code_str(enum scion_scmp_type type, uint8_t code)
{
	switch (type) {
	case SCION_SCMP_TYPE_DESTINATION_UNREACHABLE:
		return destination_unreachable_code_str((enum scion_scmp_code_destination_unreachable)code);
	case SCION_SCMP_TYPE_PARAMETER_PROBLEM:
		return parameter_problem_code_str((enum scion_scmp_code_parameter_problem)code);
	case SCION_SCMP_TYPE_PACKET_TOO_BIG:
	case SCION_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN:
	case SCION_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN:
	case SCION_SCMP_TYPE_ECHO_REQUEST:
	case SCION_SCMP_TYPE_ECHO_REPLY:
	case SCION_SCMP_TYPE_TRACEROUTE_REQUEST:
	case SCION_SCMP_TYPE_TRACEROUTE_REPLY:
		return code == 0 ? "none" : "unknown";
	}

	return "unknown";
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

// #######  Traceroute messages  #######

int scion_scmp_traceroute_serialize(const struct scion_scmp_traceroute *scmp_traceroute, uint8_t *buf, size_t buf_len)
{
	assert(scmp_traceroute);
	assert(buf);

	if (buf_len < SCION_SCMP_TRACEROUTE_LEN) {
		return SCION_ERR_BUF_TOO_SMALL;
	}

	buf[0] = (uint8_t)scmp_traceroute->type;
	buf[1] = 0;
	scion_store_be16(buf + 2, 0); // TODO checksum
	scion_store_be16(buf + 4, scmp_traceroute->id);
	scion_store_be16(buf + 6, scmp_traceroute->seqno);
	scion_store_be64(buf + 8, scmp_traceroute->ia);
	scion_store_be64(buf + 16, scmp_traceroute->interface);

	return 0;
}

int scion_scmp_traceroute_deserialize(const uint8_t *buf, size_t buf_len, struct scion_scmp_traceroute *scmp_traceroute)
{
	assert(buf || buf_len == 0);
	assert(scmp_traceroute);

	if (buf_len < SCION_SCMP_TRACEROUTE_LEN) {
		return SCION_ERR_BUF_TOO_SMALL;
	}

	if (buf[0] != SCION_SCMP_TYPE_TRACEROUTE_REQUEST && buf[0] != SCION_SCMP_TYPE_TRACEROUTE_REPLY) {
		return SCION_ERR_PACKET_FIELD_INVALID;
	}

	if (buf[1] != 0) {
		return SCION_ERR_SCMP_CODE_INVALID;
	}

	scmp_traceroute->type = (enum scion_scmp_type)buf[0];
	scmp_traceroute->id = scion_load_be16(buf + 4);
	scmp_traceroute->seqno = scion_load_be16(buf + 6);
	scmp_traceroute->ia = scion_load_be64(buf + 8);
	scmp_traceroute->interface = scion_load_be64(buf + 16);

	return 0;
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
	case SCION_SCMP_TYPE_TRACEROUTE_REQUEST:
	case SCION_SCMP_TYPE_TRACEROUTE_REPLY:
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

// Appends a formatted string to buf. used is the length the string would have if buf was large enough.
static void append(char *buf, size_t buf_len, size_t *used, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	int len;
	if (*used < buf_len) {
		len = vsnprintf(buf + *used, buf_len - *used, format, args);
	} else {
		len = vsnprintf(NULL, 0, format, args);
	}
	va_end(args);

	assert(len >= 0);
	*used += (size_t)len;
}

int scion_scmp_error_str(const struct scion_scmp_error *scmp_error, char *buf, size_t buf_len)
{
	assert(scmp_error);
	assert(buf || buf_len == 0);

	size_t used = 0;
	append(buf, buf_len, &used, "SCMP error: %s", scion_scmp_type_str(scmp_error->type));

	const char *code = scion_scmp_code_str(scmp_error->type, scmp_error->code);
	if (strcmp(code, "none") != 0) {
		append(buf, buf_len, &used, " (%s)", code);
	}

	char ia[SCION_IA_STRLEN];
	switch (scmp_error->type) {
	case SCION_SCMP_TYPE_PACKET_TOO_BIG:
		append(buf, buf_len, &used, ", MTU %" PRIu16, scmp_error->info.packet_too_big.mtu);
		break;
	case SCION_SCMP_TYPE_PARAMETER_PROBLEM:
		append(buf, buf_len, &used, ", pointer %" PRIu16, scmp_error->info.parameter_problem.pointer);
		break;
	case SCION_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN:
		(void)scion_ia_str(scmp_error->info.external_interface_down.ia, ia, sizeof(ia));
		append(buf, buf_len, &used, ", %s interface %" PRIu64, ia, scmp_error->info.external_interface_down.interface);
		break;
	case SCION_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN:
		(void)scion_ia_str(scmp_error->info.internal_connectivity_down.ia, ia, sizeof(ia));
		append(buf, buf_len, &used, ", %s interfaces %" PRIu64 ">%" PRIu64, ia,
			scmp_error->info.internal_connectivity_down.ingress_interface,
			scmp_error->info.internal_connectivity_down.egress_interface);
		break;
	default:
		// The other types carry no further information.
		break;
	}

	return used < buf_len ? 0 : SCION_ERR_BUF_TOO_SMALL;
}

void scion_scmp_error_print(const struct scion_scmp_error *scmp_error)
{
	char str[SCION_SCMP_ERROR_STRLEN];
	if (scion_scmp_error_str(scmp_error, str, sizeof(str)) == 0) {
		(void)printf("%s\n", str);
	}
}
