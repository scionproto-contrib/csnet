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

#include <stdlib.h>

#include "common/as_entry.h"

void scion_as_entry_free(struct scion_as_entry *as_entry)
{
	if (as_entry == NULL) {
		return;
	}
	if (as_entry->peer_entries != NULL) {
		for (uint16_t i = 0; i < as_entry->peer_entries_length; i++) {
			free(as_entry->peer_entries[i]);
		}
		free(as_entry->peer_entries);
	}
	free(as_entry);
}

size_t scion_as_entry_byte_size(struct scion_as_entry *as_entry)
{
	size_t size = 0;

	if (as_entry != NULL) {
		size += sizeof(struct scion_as_entry);
		// Peer Entries pointer array
		size += as_entry->peer_entries_length * sizeof(struct scion_peer_entry *);
		// Peer Entries themselves
		size += as_entry->peer_entries_length * sizeof(struct scion_peer_entry *);
	}

	return size;
}
