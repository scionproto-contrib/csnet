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

#include "scion/common/as_entry.h"
#include "scion/common/path_segment.h"

void scion_path_segment_free(struct scion_path_segment *pathseg)
{
	if (pathseg == NULL) {
		return;
	}
	if (pathseg->as_entries != NULL) {
		for (size_t i = 0; i < pathseg->as_entries_length; i++) {
			scion_as_entry_free(pathseg->as_entries[i]);
		}
		free(pathseg->as_entries);
	}
	free(pathseg);
}

size_t scion_path_segment_byte_size(struct scion_path_segment *pathseg)
{
	size_t size = 0;

	if (pathseg != NULL) {
		size += sizeof(struct scion_path_segment);
		size += pathseg->as_entries_length * sizeof(struct scion_as_entry *);
		for (size_t i = 0; i < pathseg->as_entries_length; i++) {
			size += scion_as_entry_byte_size(pathseg->as_entries[i]);
		}
	}

	return size;
}
