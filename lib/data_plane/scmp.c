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

uint8_t scion_scmp_get_type(const uint8_t *buf, uint16_t buf_len)
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

	uint8_t type = scion_scmp_get_type(buf, buf_len);
	assert(type == SCION_ECHO_TYPE_REQUEST || type == SCION_ECHO_TYPE_REPLY);

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
	scmp_echo->id = be16toh(*(uint16_t *)(buf + 4));
	scmp_echo->seqno = be16toh(*(uint16_t *)(buf + 6));

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
	*(buf + 2) = 0; // TODO checksum
	*(uint16_t *)(buf + 4) = htobe16(scmp_echo->id);
	*(uint16_t *)(buf + 6) = htobe16(scmp_echo->seqno);

	if (scmp_echo->data_length > 0) {
		(void)memcpy(buf + SCION_SCMP_ECHO_HDR_LEN, scmp_echo->data, scmp_echo->data_length);
	}

	return 0;
}

void scion_scmp_echo_free_internal(struct scion_scmp_echo *scmp_echo)
{
	free(scmp_echo->data);
	scmp_echo->data = NULL;
}
