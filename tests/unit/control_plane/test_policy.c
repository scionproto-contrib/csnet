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
#include <stdlib.h>

#include "common/path_collection.h"
#include "control_plane/policy.h"
#include "data_plane/path.h"
#include "scion/scion.h"
#include "test_policy.h"
#include "util/list.h"

static int teardown_collection(void **state)
{
	scion_path_collection_free(*state);
	return 0;
}

static struct scion_path_collection *make_collection(void **state)
{
	struct scion_path_collection *collection;
	assert_int_equal(scion_path_collection_init(&collection), 0);
	*state = collection;
	return collection;
}

// A SCION path with interfaces_len interfaces (so interfaces_len / 2 + 1 hops) and no latency or bandwidth info.
static struct scion_path *add_path(struct scion_path_collection *collection, size_t interfaces_len, uint32_t mtu)
{
	struct scion_path *path = calloc(1, sizeof(*path));
	path->path_type = SCION_PATH_TYPE_SCION;
	path->metadata = calloc(1, sizeof(*path->metadata));
	path->metadata->interfaces = calloc(interfaces_len, sizeof(*path->metadata->interfaces));
	path->metadata->interfaces_len = interfaces_len;
	path->metadata->mtu = mtu;
	scion_list_append(collection->list, path);
	return path;
}

// One entry per hop between consecutive interfaces. -1 marks the latency as unset.
static void set_latencies(struct scion_path *path, const long *microseconds)
{
	size_t len = path->metadata->interfaces_len - 1;
	path->metadata->latencies = calloc(len, sizeof(*path->metadata->latencies));
	for (size_t i = 0; i < len; i++) {
		path->metadata->latencies[i].tv_sec = 0;
		path->metadata->latencies[i].tv_usec = microseconds[i];
	}
}

// One entry per hop between consecutive interfaces. 0 marks the bandwidth as unset.
static void set_bandwidths(struct scion_path *path, const uint64_t *bandwidths)
{
	size_t len = path->metadata->interfaces_len - 1;
	path->metadata->bandwidths = calloc(len, sizeof(*path->metadata->bandwidths));
	for (size_t i = 0; i < len; i++) {
		path->metadata->bandwidths[i] = bandwidths[i];
	}
}

static void assert_order(struct scion_path_collection *collection, struct scion_path **expected, size_t len)
{
	assert_uint_equal(scion_path_collection_size(collection), len);
	for (size_t i = 0; i < len; i++) {
		assert_ptr_equal(scion_list_get(collection->list, i), expected[i]);
	}
}

static void test_policy_least_hops(void **state)
{
	struct scion_path_collection *collection = make_collection(state);
	struct scion_path *four_hops = add_path(collection, 6, 1280);
	struct scion_path *two_hops = add_path(collection, 2, 1280);
	struct scion_path *three_hops = add_path(collection, 4, 1280);

	scion_policy_least_hops.fn(collection, scion_policy_least_hops.ctx);

	assert_order(collection, (struct scion_path *[]){ two_hops, three_hops, four_hops }, 3);
}

static void test_policy_highest_mtu(void **state)
{
	struct scion_path_collection *collection = make_collection(state);
	struct scion_path *low = add_path(collection, 2, 1280);
	struct scion_path *high = add_path(collection, 2, 1500);
	struct scion_path *mid = add_path(collection, 2, 1400);

	scion_policy_highest_mtu.fn(collection, scion_policy_highest_mtu.ctx);

	assert_order(collection, (struct scion_path *[]){ high, mid, low }, 3);
}

static void test_policy_highest_mtu_tie_prefers_fewer_hops(void **state)
{
	struct scion_path_collection *collection = make_collection(state);
	struct scion_path *three_hops = add_path(collection, 4, 1400);
	struct scion_path *two_hops = add_path(collection, 2, 1400);

	scion_policy_highest_mtu.fn(collection, scion_policy_highest_mtu.ctx);

	assert_order(collection, (struct scion_path *[]){ two_hops, three_hops }, 2);
}

// Paths with a fully known latency come first, lowest total first. The rest follow, fewest hops first.
static void test_policy_lowest_latency(void **state)
{
	struct scion_path_collection *collection = make_collection(state);

	struct scion_path *slow = add_path(collection, 4, 1400);
	set_latencies(slow, (long[]){ 10000, 10000, 10000 });

	struct scion_path *fast = add_path(collection, 4, 1400);
	set_latencies(fast, (long[]){ 2000, 2000, 2000 });

	struct scion_path *partially_known = add_path(collection, 4, 1400);
	set_latencies(partially_known, (long[]){ 5000, -1, 5000 });

	struct scion_path *no_latencies = add_path(collection, 2, 1400);

	scion_policy_lowest_latency.fn(collection, scion_policy_lowest_latency.ctx);

	assert_order(collection, (struct scion_path *[]){ fast, slow, no_latencies, partially_known }, 4);
}

// Paths with a fully known bandwidth come first, highest bottleneck first. The rest follow, fewest hops first.
static void test_policy_highest_bandwidth(void **state)
{
	struct scion_path_collection *collection = make_collection(state);

	struct scion_path *bottleneck = add_path(collection, 4, 1400);
	set_bandwidths(bottleneck, (uint64_t[]){ 1000, 500, 1000 });

	struct scion_path *wide = add_path(collection, 4, 1400);
	set_bandwidths(wide, (uint64_t[]){ 2000, 2000, 2000 });

	struct scion_path *partially_known = add_path(collection, 4, 1400);
	set_bandwidths(partially_known, (uint64_t[]){ 800, 0, 800 });

	struct scion_path *no_bandwidths = add_path(collection, 2, 1400);

	scion_policy_highest_bandwidth.fn(collection, scion_policy_highest_bandwidth.ctx);

	assert_order(collection, (struct scion_path *[]){ wide, bottleneck, no_bandwidths, partially_known }, 4);
}

static void test_policy_min_mtu(void **state)
{
	struct scion_path_collection *collection = make_collection(state);
	add_path(collection, 2, 1280);
	struct scion_path *high = add_path(collection, 2, 1500);
	struct scion_path *exact = add_path(collection, 2, 1400);

	uint32_t min_mtu = 1400;
	struct scion_policy policy = scion_policy_min_mtu(&min_mtu);
	policy.fn(collection, policy.ctx);

	assert_order(collection, (struct scion_path *[]){ high, exact }, 2);
}

int run_policy_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_teardown(test_policy_least_hops, teardown_collection),
		cmocka_unit_test_teardown(test_policy_highest_mtu, teardown_collection),
		cmocka_unit_test_teardown(test_policy_highest_mtu_tie_prefers_fewer_hops, teardown_collection),
		cmocka_unit_test_teardown(test_policy_lowest_latency, teardown_collection),
		cmocka_unit_test_teardown(test_policy_highest_bandwidth, teardown_collection),
		cmocka_unit_test_teardown(test_policy_min_mtu, teardown_collection),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
