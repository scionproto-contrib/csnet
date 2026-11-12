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

#pragma once

#include <stdint.h>

#include "common/isd_as.h"
#include "scion/scion_path.h"

#define SCION_PATH_CACHE_SIZE 8

struct scion_path_cache_entry {
	scion_ia dst_ia;
	// NULL if the entry is not used
	struct scion_path_collection *paths;
	uint64_t last_used;
};

/**
 * The paths to the destinations that a socket sends to without being connected to them, so they are not fetched for
 * every packet. When the cache is full, the least recently used destination is evicted. A zero-initialized cache is
 * empty.
 */
struct scion_path_cache {
	struct scion_path_cache_entry entries[SCION_PATH_CACHE_SIZE];
	uint64_t clock;
};

/**
 * Gets the paths to a destination. Returns NULL if they are not in the cache.
 */
struct scion_path_collection *scion_path_cache_get(struct scion_path_cache *cache, scion_ia dst_ia);

/**
 * Adds the paths to a destination, which the cache then owns. They replace the paths that the destination had.
 */
void scion_path_cache_put(struct scion_path_cache *cache, scion_ia dst_ia, struct scion_path_collection *paths);

/**
 * Frees all the paths of the cache, which is then empty.
 */
void scion_path_cache_clear(struct scion_path_cache *cache);
