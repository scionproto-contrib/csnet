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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>

#define SCION_MAP_CUSTOM_FREE(free_fn) \
	((struct scion_map_value_free){ .fn = (scion_map_value_free_fn)scion_map_value_free_wrapper, .ctx = (free_fn) })
#define SCION_MAP_CUSTOM_FREE_WITH_CTX(free_fn, ctx_arg) \
	((struct scion_map_value_free){ .fn = (scion_map_value_free_fn)(free_fn), .ctx = (ctx_arg) })

#define SCION_MAP_NO_FREE_VALUES SCION_MAP_CUSTOM_FREE(NULL)
#define SCION_MAP_SIMPLE_FREE SCION_MAP_CUSTOM_FREE(free)

typedef void (*scion_map_value_free_fn)(void *value, void *ctx);

struct scion_map_value_free {
	scion_map_value_free_fn fn;
	void *ctx;
};

typedef void (*scion_map_serialize_key)(void *key, void *buffer);

struct scion_map_key_config {
	size_t size;
	scion_map_serialize_key serialize;
};

struct scion_map {
	struct scion_map_key_config key_config;

	struct scion_linked_list *key_value_pairs;

	struct scion_map_value_free free_value;
};

struct scion_map_key_value_pair {
	void *key;
	void *value;
};

void scion_map_value_free_wrapper(void *value, void (*free_fn)(void *));

struct scion_map *scion_map_create(struct scion_map_key_config key_config, struct scion_map_value_free free_value);

void scion_map_put(struct scion_map *map, void *key, void *value);

void *scion_map_get(struct scion_map *map, void *key);

void scion_map_free(struct scion_map *map);
