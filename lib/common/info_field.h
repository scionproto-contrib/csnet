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

#include <stdbool.h>
#include <stdint.h>

#include "scion/scion.h"

/*
 * Implementation of InfoField.
 * Mostly in line with the GO implementation. Documentation also taken from the GO implementation.
 * https://github.com/scionproto/scion/blob/master/pkg/slayers/path/infofield.go (Last visited May 30th 2024)
 *
 */

// SCION_INFO_LEN is the size of an InfoField in bytes.
#define SCION_INFO_LEN 8

// scion_info_field is the InfoField used in the SCION and OneHop path types.
struct scion_info_field {
	// peer is the peering flag. If set to true, then the forwarding path is built as a peering
	// path, which requires special processing on the dataplane.
	bool peer;
	// cons_dir is the construction direction flag. If set to true then the hop fields are arranged
	// in the direction they have been constructed during beaconing.
	bool cons_dir;
	// seg_id is an updatable field that is required for the MAC-chaining mechanism.
	uint16_t seg_id;
	// timestamp created by the initiator of the corresponding beacon. The timestamp is expressed in
	// Unix time, and is encoded as an unsigned integer within 4 bytes with 1-second time
	// granularity.  This timestamp enables validation of the hop field by verification of the
	// expiration time and MAC.
	uint32_t timestamp;
};

int scion_info_field_serialize(uint8_t *buf, struct scion_info_field *info_field);

int scion_info_field_deserialize(const uint8_t *buf, struct scion_info_field *info_field);
