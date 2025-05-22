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

#include "map.h"

#include "list.h"

#include <stdlib.h>
#include <string.h>

struct match_key_ctx {
	void *serialized_key;
	size_t key_size;
};

static bool match_key(struct scion_map_key_value_pair *key_value_pair, struct match_key_ctx *ctx)
{
	return memcmp(key_value_pair->key, ctx->serialized_key, ctx->key_size) == 0;
}

static void *serialize_key(struct scion_map *map, void *key)
{
	void *serialized_key = malloc(map->key_config.size);

	if (map->key_config.serialize != NULL) {
		map->key_config.serialize(key, serialized_key);
	} else {
		(void)memcpy(serialized_key, key, map->key_config.size);
	}

	return serialized_key;
}

static void free_key_value(struct scion_map_key_value_pair *entry, struct scion_map_value_free *free_value)
{
	if (entry == NULL) {
		return;
	}

	free(entry->key);

	if (free_value->fn != NULL) {
		free_value->fn(entry->value, free_value->ctx);
	}

	free(entry);
}

struct scion_map *scion_map_create(struct scion_map_key_config key_config, struct scion_map_value_free free_value)
{
	struct scion_map *map = malloc(sizeof(*map));
	map->key_config = key_config;

	map->free_value = free_value;
	map->key_value_pairs = scion_list_create(SCION_LIST_CUSTOM_FREE_WITH_CTX(free_key_value, &map->free_value));

	return map;
}

static struct scion_map_key_value_pair *get_key(struct scion_map *map, void *key)
{
	void *serialized_key = serialize_key(map, key);

	struct match_key_ctx ctx = { .serialized_key = serialized_key, .key_size = map->key_config.size };
	struct scion_list_predicate predicate = { .fn = (scion_list_predicate_fn)match_key, .ctx = &ctx };

	struct scion_map_key_value_pair *kvp = scion_list_find(map->key_value_pairs, predicate);

	free(serialized_key);
	return kvp;
}

void scion_map_put(struct scion_map *map, void *key, void *value)
{
	struct scion_map_key_value_pair *entry = get_key(map, key);

	if (entry == NULL) {
		// insert value
		void *serialized_key = serialize_key(map, key);

		struct scion_map_key_value_pair *new_entry = malloc(sizeof(*new_entry));
		new_entry->key = serialized_key;
		new_entry->value = value;
		scion_list_append(map->key_value_pairs, new_entry);
	} else {
		// free old value
		if (map->free_value.fn != NULL) {
			map->free_value.fn(entry->value, map->free_value.ctx);
		}

		// set new value
		entry->value = value;
	}
}

void *scion_map_get(struct scion_map *map, void *key)
{
	struct scion_map_key_value_pair *entry = get_key(map, key);

	if (entry == NULL) {
		return NULL;
	}

	return entry->value;
}

void scion_map_free(struct scion_map *map)
{
	if (map == NULL) {
		return;
	}

	scion_list_free(map->key_value_pairs);

	free(map);
}

void scion_map_value_free_wrapper(void *value, void (*free_fn)(void *))
{
	if (free_fn == NULL) {
		return;
	}

	free_fn(value);
}
