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

#include "common/info_field.h"
#include "util/endian.h"

// scion_info_field will be serialized to the following format:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|r r r r r r P C|      RSV      |             SegID             |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                           Timestamp                           |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

int scion_info_field_serialize(uint8_t *buf, struct scion_info_field *info_field)
{
	assert(buf);
	assert(info_field);

	buf[0] = 0;
	if (info_field->cons_dir) {
		buf[0] |= 0x1;
	}
	if (info_field->peer) {
		buf[0] |= 0x2;
	}
	buf[1] = 0; // reserved
	scion_store_be16(buf + 2, info_field->seg_id);
	scion_store_be32(buf + 4, info_field->timestamp);
	return 0;
}

int scion_info_field_deserialize(const uint8_t *buf, struct scion_info_field *info_field)
{
	assert(buf);
	assert(info_field);

	info_field->cons_dir = ((buf[0] & 0x1) == 0x1);
	info_field->peer = ((buf[0] & 0x2) == 0x2);
	info_field->seg_id = scion_load_be16(buf + 2);
	info_field->timestamp = scion_load_be32(buf + 4);
	return 0;
}
