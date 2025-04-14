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

#include <stdint.h>
#include <stdlib.h>

#include "scion/common/as_entry.h"
#include "scion/common/hop_field.h"
#include "scion/error.h"

#include <assert.h>
#include <string.h>

// The Hop Field will be serialized to the following format:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|r r r r r r I E|    ExpTime    |           ConsIngress         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|        ConsEgress             |                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
//	|                              MAC                              |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

int scion_hop_field_serialize(uint8_t *buf, struct scion_hop_field *hop_field)
{
	assert(buf);
	assert(hop_field);

	buf[0] = 0;
	if (hop_field->egress_router_alert) {
		buf[0] |= 0x1;
	}
	if (hop_field->ingress_router_alert) {
		buf[0] |= 0x2;
	}
	buf[1] = hop_field->exp_time;
	*(uint16_t *)(buf + 2) = htobe16(hop_field->cons_ingress);
	*(uint16_t *)(buf + 4) = htobe16(hop_field->cons_egress);
	(void)memcpy(buf + 6, hop_field->mac, SCION_MAC_LEN);
	return 0;
}

int scion_hop_field_deserialize(uint8_t *buf, struct scion_hop_field *hop_field)
{
	assert(buf);
	assert(hop_field);

	hop_field->egress_router_alert = ((buf[0] & 0x1) == 0x1);
	hop_field->ingress_router_alert = ((buf[0] & 0x2) == 0x2);
	hop_field->exp_time = buf[1];
	hop_field->cons_ingress = be16toh(*(uint16_t *)(buf + 2));
	hop_field->cons_egress = be16toh(*(uint16_t *)(buf + 4));
	(void)memcpy(hop_field->mac, buf + 6, SCION_MAC_LEN);
	return 0;
}
