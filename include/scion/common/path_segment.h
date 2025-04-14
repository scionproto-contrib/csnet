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

#include "scion/common/as_entry.h"

enum scion_segment_type {
	UNSPECIFIED_SEGMENT = 0,
	UP_SEGMENT = 1,
	DOWN_SEGMENT = 2,
	CORE_SEGMENT = 3,
};

struct scion_segment_info {
	int64_t timestamp;
	uint16_t segment_id;
};

struct scion_path_segment {
	struct scion_segment_info info;
	struct scion_as_entry **as_entries;
	size_t as_entries_length;
};

void scion_path_segment_free(struct scion_path_segment *pathseg);

size_t scion_path_segment_byte_size(struct scion_path_segment *pathseg);
