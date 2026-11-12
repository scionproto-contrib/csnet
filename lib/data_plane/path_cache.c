// Copyright 2026 ETH Zurich
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
#include <stddef.h>

#include "common/path_collection.h"
#include "data_plane/path_cache.h"

static struct scion_path_cache_entry *find_entry(struct scion_path_cache *cache, scion_ia dst_ia)
{
	for (size_t i = 0; i < SCION_PATH_CACHE_SIZE; i++) {
		struct scion_path_cache_entry *entry = &cache->entries[i];
		if (entry->paths != NULL && entry->dst_ia == dst_ia) {
			return entry;
		}
	}

	return NULL;
}

// An unused entry, or the least recently used one if all are used.
static struct scion_path_cache_entry *free_entry(struct scion_path_cache *cache)
{
	struct scion_path_cache_entry *oldest = &cache->entries[0];
	for (size_t i = 0; i < SCION_PATH_CACHE_SIZE; i++) {
		struct scion_path_cache_entry *entry = &cache->entries[i];
		if (entry->paths == NULL) {
			return entry;
		}
		if (entry->last_used < oldest->last_used) {
			oldest = entry;
		}
	}

	return oldest;
}

struct scion_path_collection *scion_path_cache_get(struct scion_path_cache *cache, scion_ia dst_ia)
{
	assert(cache);

	struct scion_path_cache_entry *entry = find_entry(cache, dst_ia);
	if (entry == NULL) {
		return NULL;
	}

	entry->last_used = ++cache->clock;
	return entry->paths;
}

void scion_path_cache_put(struct scion_path_cache *cache, scion_ia dst_ia, struct scion_path_collection *paths)
{
	assert(cache);
	assert(paths);

	struct scion_path_cache_entry *entry = find_entry(cache, dst_ia);
	if (entry == NULL) {
		entry = free_entry(cache);
	}

	if (entry->paths != paths) {
		scion_path_collection_free(entry->paths);
	}

	entry->dst_ia = dst_ia;
	entry->paths = paths;
	entry->last_used = ++cache->clock;
}

void scion_path_cache_clear(struct scion_path_cache *cache)
{
	assert(cache);

	for (size_t i = 0; i < SCION_PATH_CACHE_SIZE; i++) {
		scion_path_collection_free(cache->entries[i].paths);
		cache->entries[i].paths = NULL;
	}
}
