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

#include "test_map.h"
#include "util/map.h"

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

int run_map_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_map_example),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
