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

#include <cmocka.h>

#include "common/path_collection.h"
#include "data_plane/path_cache.h"
#include "test_path_cache.h"

static struct scion_path_collection *empty_collection(void)
{
	struct scion_path_collection *paths;
	assert_int_equal(scion_path_collection_init(&paths), 0);
	return paths;
}

static void test_path_cache_empty(void **)
{
	struct scion_path_cache cache = { 0 };

	assert_null(scion_path_cache_get(&cache, 1));
}

static void test_path_cache_put_and_get(void **)
{
	struct scion_path_cache cache = { 0 };
	struct scion_path_collection *paths = empty_collection();

	scion_path_cache_put(&cache, 1, paths);

	assert_ptr_equal(scion_path_cache_get(&cache, 1), paths);
	assert_null(scion_path_cache_get(&cache, 2));
	scion_path_cache_clear(&cache);
}

static void test_path_cache_put_replaces_the_paths(void **)
{
	struct scion_path_cache cache = { 0 };
	struct scion_path_collection *new_paths = empty_collection();

	scion_path_cache_put(&cache, 1, empty_collection());
	scion_path_cache_put(&cache, 1, new_paths);

	assert_ptr_equal(scion_path_cache_get(&cache, 1), new_paths);
	scion_path_cache_clear(&cache);
}

static void test_path_cache_evicts_the_least_recently_used(void **)
{
	// Fill the cache with the destinations 1 to SCION_PATH_CACHE_SIZE, in this order of use
	struct scion_path_cache cache = { 0 };
	for (scion_ia ia = 1; ia <= SCION_PATH_CACHE_SIZE; ia++) {
		scion_path_cache_put(&cache, ia, empty_collection());
	}

	// Destination 1 is the least recently used. Getting it makes it the most recently used, so 2 becomes the least.
	assert_non_null(scion_path_cache_get(&cache, 1));

	// The cache is full, so adding one more destination evicts the least recently used one, 2
	scion_path_cache_put(&cache, SCION_PATH_CACHE_SIZE + 1, empty_collection());

	// Only destination 2 is gone, 1 is kept because it was used again
	assert_non_null(scion_path_cache_get(&cache, 1));
	assert_null(scion_path_cache_get(&cache, 2));
	for (scion_ia ia = 3; ia <= SCION_PATH_CACHE_SIZE + 1; ia++) {
		assert_non_null(scion_path_cache_get(&cache, ia));
	}
	scion_path_cache_clear(&cache);
}

static void test_path_cache_clear(void **)
{
	struct scion_path_cache cache = { 0 };
	scion_path_cache_put(&cache, 1, empty_collection());

	scion_path_cache_clear(&cache);

	assert_null(scion_path_cache_get(&cache, 1));
}

int run_path_cache_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_path_cache_empty),
		cmocka_unit_test(test_path_cache_put_and_get),
		cmocka_unit_test(test_path_cache_put_replaces_the_paths),
		cmocka_unit_test(test_path_cache_evicts_the_least_recently_used),
		cmocka_unit_test(test_path_cache_clear),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
