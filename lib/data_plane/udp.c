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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "data_plane/udp.h"
#include "util/endian.h"

uint16_t scion_udp_len(struct scion_udp *udp)
{
	return SCION_UDP_HDR_LEN + udp->data_length;
}

void scion_udp_free_internal(struct scion_udp *udp)
{
	if (udp == NULL) {
		return;
	}

	if (udp->data != NULL) {
		free(udp->data);
		udp->data = NULL;
	}
}

/*
 * ##################################################################
 * ###################### Serialize Payloads ########################
 * ##################################################################
 */

int scion_udp_serialize(struct scion_udp *udp, uint8_t *buf, uint16_t *len)
{
	assert(udp);
	assert(buf);
	assert(len);

	(void)memset(buf, 0, *len);

	if (SCION_UDP_HDR_LEN + (uint32_t)udp->data_length > UINT16_MAX) {
		return SCION_ERR_MSG_TOO_LARGE;
	}

	uint16_t udp_len = scion_udp_len(udp);

	if (*len < udp_len) {
		return SCION_ERR_BUF_TOO_SMALL;
	}

	*(uint16_t *)(buf) = htobe16(udp->src_port);
	*(uint16_t *)(buf + 2) = htobe16(udp->dst_port);
	*(uint16_t *)(buf + 4) = htobe16(udp_len);

	// TODO calculate checksum
	if (udp->data_length > 0) {
		(void)memcpy(buf + 8, udp->data, udp->data_length);
	}

	return 0;
}

int scion_udp_deserialize(const uint8_t *buf, uint16_t len, struct scion_udp *udp)
{
	assert(udp);
	assert(buf);

	if (len < SCION_UDP_HDR_LEN) {
		// incomplete header
		return SCION_ERR_NOT_ENOUGH_DATA;
	}

	udp->src_port = be16toh(*(uint16_t *)buf);
	udp->dst_port = be16toh(*(uint16_t *)(buf + 2));
	uint16_t udp_len = be16toh(*(uint16_t *)(buf + 4));

	if (len < udp_len) {
		// incomplete packet
		return SCION_ERR_NOT_ENOUGH_DATA;
	}

	udp->data_length = udp_len - SCION_UDP_HDR_LEN;

	if (udp->data_length > 0) {
		udp->data = (uint8_t *)malloc(udp->data_length);
		(void)memcpy(udp->data, buf + 8, udp->data_length);
	} else {
		udp->data = NULL;
	}

	return 0;
}
