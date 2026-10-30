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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// The table doubles whenever there are more pairs than buckets
#define INITIAL_NUM_BUCKETS 16

// 32-bit FNV-1a, see http://www.isthe.com/chongo/tech/comp/fnv/index.html
#define FNV_OFFSET_BASIS 2166136261U
#define FNV_PRIME 16777619U

static uint32_t hash_key(const void *key, size_t size)
{
	const unsigned char *bytes = key;
	uint32_t hash = FNV_OFFSET_BASIS;
	for (size_t i = 0; i < size; i++) {
		hash ^= bytes[i];
		hash *= FNV_PRIME;
	}
	return hash;
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

	map->num_buckets = INITIAL_NUM_BUCKETS;
	map->buckets = calloc(map->num_buckets, sizeof(*map->buckets));

	return map;
}

static struct scion_map_key_value_pair *find_pair(struct scion_map *map, const void *serialized_key, uint32_t hash)
{
	for (struct scion_map_bucket_entry *entry = map->buckets[hash % map->num_buckets]; entry != NULL;
		 entry = entry->next) {
		if (entry->hash == hash && memcmp(entry->pair->key, serialized_key, map->key_config.size) == 0) {
			return entry->pair;
		}
	}

	return NULL;
}

// Doubles the number of buckets once there are more pairs than buckets
static void grow_buckets(struct scion_map *map)
{
	if (scion_list_size(map->key_value_pairs) <= map->num_buckets) {
		return;
	}

	size_t num_buckets = map->num_buckets * 2;
	struct scion_map_bucket_entry **buckets = calloc(num_buckets, sizeof(*buckets));

	for (size_t i = 0; i < map->num_buckets; i++) {
		struct scion_map_bucket_entry *entry = map->buckets[i];
		while (entry != NULL) {
			struct scion_map_bucket_entry *next = entry->next;
			entry->next = buckets[entry->hash % num_buckets];
			buckets[entry->hash % num_buckets] = entry;
			entry = next;
		}
	}

	free(map->buckets);
	map->buckets = buckets;
	map->num_buckets = num_buckets;
}

void scion_map_put(struct scion_map *map, void *key, void *value)
{
	void *serialized_key = serialize_key(map, key);
	uint32_t hash = hash_key(serialized_key, map->key_config.size);
	struct scion_map_key_value_pair *pair = find_pair(map, serialized_key, hash);

	if (pair == NULL) {
		// insert value
		struct scion_map_key_value_pair *new_pair = malloc(sizeof(*new_pair));
		new_pair->key = serialized_key;
		new_pair->value = value;
		scion_list_append(map->key_value_pairs, new_pair);

		struct scion_map_bucket_entry *entry = malloc(sizeof(*entry));
		entry->pair = new_pair;
		entry->hash = hash;
		entry->next = map->buckets[hash % map->num_buckets];
		map->buckets[hash % map->num_buckets] = entry;

		grow_buckets(map);
	} else {
		free(serialized_key);

		// free old value
		if (map->free_value.fn != NULL) {
			map->free_value.fn(pair->value, map->free_value.ctx);
		}

		// set new value
		pair->value = value;
	}
}

void *scion_map_get(struct scion_map *map, void *key)
{
	void *serialized_key = serialize_key(map, key);
	uint32_t hash = hash_key(serialized_key, map->key_config.size);
	struct scion_map_key_value_pair *pair = find_pair(map, serialized_key, hash);
	free(serialized_key);

	if (pair == NULL) {
		return NULL;
	}

	return pair->value;
}

void scion_map_free(struct scion_map *map)
{
	if (map == NULL) {
		return;
	}

	for (size_t i = 0; i < map->num_buckets; i++) {
		struct scion_map_bucket_entry *entry = map->buckets[i];
		while (entry != NULL) {
			struct scion_map_bucket_entry *next = entry->next;
			free(entry);
			entry = next;
		}
	}
	free(map->buckets);

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
