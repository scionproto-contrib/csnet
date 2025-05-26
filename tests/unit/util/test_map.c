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

#include "test_map.h"
#include "util/map.h"

#include <stdint.h>

int scion_test_map_example(void)
{
	int ret = 0;

	struct scion_map *map = scion_map_create(
		(struct scion_map_key_config){ .size = sizeof(uint32_t), .serialize = NULL }, SCION_MAP_NO_FREE_VALUES);

	int values[] = { 100, -1, 3, 16 };

	uint32_t keys[] = { 3, 4 };
	if (scion_map_get(map, &keys[0]) != NULL) {
		ret = 1;
		goto cleanup_map;
	}

	scion_map_put(map, &keys[0], &values[0]);
	if (scion_map_get(map, &keys[0]) != &values[0]) {
		ret = 2;
		goto cleanup_map;
	}

	scion_map_put(map, &keys[0], &values[1]);
	if (scion_map_get(map, &keys[0]) != &values[1]) {
		ret = 3;
		goto cleanup_map;
	}

	scion_map_put(map, &keys[1], &values[2]);
	if (scion_map_get(map, &keys[0]) != &values[1] || scion_map_get(map, &keys[1]) != &values[2]) {
		ret = 4;
	}

cleanup_map:
	scion_map_free(map);

	return ret;
}
