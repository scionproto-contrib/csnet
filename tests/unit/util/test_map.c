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

#include <cmocka.h>
#include <stdint.h>
#include <string.h>

#include "test_map.h"
#include "util/list.h"
#include "util/map.h"

static void serialize_low_half(void *key, void *buffer)
{
	uint16_t low = (uint16_t)(*(uint32_t *)key & 0xFFFF);
	memcpy(buffer, &low, sizeof(low));
}

static void test_map_example(void **)
{
	struct scion_map *map = scion_map_create(
		(struct scion_map_key_config){ .size = sizeof(uint32_t), .serialize = NULL }, SCION_MAP_NO_FREE_VALUES);

	int values[] = { 100, -1, 3, 16 };
	uint32_t keys[] = { 3, 4 };

	assert_null(scion_map_get(map, &keys[0]));

	scion_map_put(map, &keys[0], &values[0]);
	assert_ptr_equal(scion_map_get(map, &keys[0]), &values[0]);

	scion_map_put(map, &keys[0], &values[1]);
	assert_ptr_equal(scion_map_get(map, &keys[0]), &values[1]);

	scion_map_put(map, &keys[1], &values[2]);
	assert_ptr_equal(scion_map_get(map, &keys[0]), &values[1]);
	assert_ptr_equal(scion_map_get(map, &keys[1]), &values[2]);

	scion_map_free(map);
}

static void test_map_many_keys(void **)
{
	struct scion_map *map = scion_map_create(
		(struct scion_map_key_config){ .size = sizeof(uint32_t), .serialize = NULL }, SCION_MAP_NO_FREE_VALUES);

	enum { NUM_KEYS = 1000 };
	uint32_t keys[NUM_KEYS];
	uint32_t values[NUM_KEYS];
	for (uint32_t i = 0; i < NUM_KEYS; i++) {
		keys[i] = i * 7;
		values[i] = i;
		scion_map_put(map, &keys[i], &values[i]);
	}

	// The map has grown several times, all the keys must still be found
	for (uint32_t i = 0; i < NUM_KEYS; i++) {
		assert_ptr_equal(scion_map_get(map, &keys[i]), &values[i]);
	}

	uint32_t missing = 1;
	assert_null(scion_map_get(map, &missing));

	// Replacing keeps one pair per key
	uint32_t replacement = 42;
	scion_map_put(map, &keys[10], &replacement);
	assert_ptr_equal(scion_map_get(map, &keys[10]), &replacement);
	assert_int_equal(scion_list_size(map->key_value_pairs), NUM_KEYS);

	scion_map_free(map);
}

static void test_map_serialized_keys(void **)
{
	struct scion_map *map = scion_map_create(
		(struct scion_map_key_config){ .size = sizeof(uint16_t), .serialize = serialize_low_half },
		SCION_MAP_NO_FREE_VALUES);

	// The keys are equal once serialized
	uint32_t key_a = 0x00010005;
	uint32_t key_b = 0x00020005;
	uint32_t key_c = 0x00010006;
	int value = 1;
	scion_map_put(map, &key_a, &value);

	assert_ptr_equal(scion_map_get(map, &key_b), &value);
	assert_null(scion_map_get(map, &key_c));
	assert_int_equal(scion_list_size(map->key_value_pairs), 1);

	scion_map_free(map);
}

static void test_map_frees_replaced_and_remaining_values(void **)
{
	struct scion_map *map = scion_map_create(
		(struct scion_map_key_config){ .size = sizeof(uint32_t), .serialize = NULL }, SCION_MAP_SIMPLE_FREE);

	uint32_t key = 1;
	scion_map_put(map, &key, malloc(1));
	scion_map_put(map, &key, malloc(1));
	key = 2;
	scion_map_put(map, &key, malloc(1));

	// Leak checkers fail the test if a value is not freed
	scion_map_free(map);
}

int run_map_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_map_example),
		cmocka_unit_test(test_map_many_keys),
		cmocka_unit_test(test_map_serialized_keys),
		cmocka_unit_test(test_map_frees_replaced_and_remaining_values),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
