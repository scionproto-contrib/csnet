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
#include "data_plane/path.h"
#include "data_plane/selector.h"
#include "scion/scion.h"
#include "scion/scion_path.h"
#include "scion/scion_selector.h"
#include "test_selector.h"
#include "util/list.h"

#define MAX_COLLECTIONS 3

struct selector_state {
	struct scion_path_collection *collections[MAX_COLLECTIONS];
	size_t collections_len;
};

struct hop {
	scion_ia ia;
	scion_ifid id;
};

// The interfaces of the paths, each hop with its AS. The paths from AS 1 to AS 3 pass through AS 2, 4 and 5.
static const struct hop via_2[] = { { 1, 1 }, { 2, 1 }, { 2, 2 }, { 3, 1 } };
static const struct hop via_2_other_interface[] = { { 1, 4 }, { 2, 1 }, { 2, 3 }, { 3, 4 } };
static const struct hop via_4[] = { { 1, 2 }, { 4, 1 }, { 4, 2 }, { 3, 2 } };
static const struct hop via_5[] = { { 1, 3 }, { 5, 1 }, { 5, 2 }, { 3, 3 } };

static int setup_selector(void **state)
{
	*state = calloc(1, sizeof(struct selector_state));
	return 0;
}

static int teardown_selector(void **state)
{
	struct selector_state *s = *state;
	for (size_t i = 0; i < s->collections_len; i++) {
		scion_path_collection_free(s->collections[i]);
	}
	free(s);
	return 0;
}

static struct scion_path *make_path(const struct hop *hops, size_t len)
{
	struct scion_path *path = calloc(1, sizeof(*path));
	path->path_type = SCION_PATH_TYPE_SCION;
	path->metadata = calloc(1, sizeof(*path->metadata));
	path->metadata->interfaces = calloc(len, sizeof(*path->metadata->interfaces));
	path->metadata->interfaces_len = len;
	for (size_t i = 0; i < len; i++) {
		path->metadata->interfaces[i].ia = hops[i].ia;
		path->metadata->interfaces[i].id = hops[i].id;
	}
	return path;
}

#define MAKE_PATH(hops) make_path(hops, sizeof(hops) / sizeof((hops)[0]))

// A collection of paths, in the order of the arguments.
static struct scion_path_collection *make_collection(
	struct selector_state *s, struct scion_path **paths, const struct hop *const *hops, const size_t *lens, size_t len)
{
	assert_true(s->collections_len < MAX_COLLECTIONS);
	struct scion_path_collection *collection;
	assert_int_equal(scion_path_collection_init(&collection), 0);
	s->collections[s->collections_len++] = collection;

	for (size_t i = 0; i < len; i++) {
		paths[i] = make_path(hops[i], lens[i]);
		scion_list_append(collection->list, paths[i]);
	}
	return collection;
}

// The paths via AS 2, 4 and 5, in this order.
static struct scion_path_collection *make_three_paths(struct selector_state *s, struct scion_path **paths)
{
	const struct hop *hops[] = { via_2, via_4, via_5 };
	const size_t lens[] = { 4, 4, 4 };
	return make_collection(s, paths, hops, lens, 3);
}

static struct scion_path *select_path(struct scion_path_collection *paths, const struct scion_path *current)
{
	return scion_selector_default.fn(paths, current, scion_selector_default.ctx);
}

static void report_external_interface_down(struct scion_path_collection *paths, scion_ia ia, scion_ifid interface)
{
	struct scion_scmp_error error = { .type = SCION_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN,
		.info.external_interface_down = { .ia = ia, .interface = interface } };
	scion_path_collection_mark_down(paths, &error);
}

static void test_selector_without_paths(void **state)
{
	struct selector_state *s = *state;
	struct scion_path_collection *empty;
	assert_int_equal(scion_path_collection_init(&empty), 0);
	s->collections[s->collections_len++] = empty;

	assert_null(select_path(empty, NULL));
}

static void test_selector_uses_the_first_path(void **state)
{
	struct selector_state *s = *state;
	struct scion_path *paths[3];
	struct scion_path_collection *collection = make_three_paths(s, paths);

	assert_ptr_equal(select_path(collection, NULL), paths[0]);
}

static void test_selector_keeps_the_current_path(void **state)
{
	struct selector_state *s = *state;
	struct scion_path *paths[3];
	struct scion_path_collection *collection = make_three_paths(s, paths);

	assert_ptr_equal(select_path(collection, paths[1]), paths[1]);
	assert_ptr_equal(select_path(collection, paths[2]), paths[2]);
}

static void test_selector_switches_if_current_down(void **state)
{
	struct selector_state *s = *state;
	struct scion_path *paths[3];
	struct scion_path_collection *collection = make_three_paths(s, paths);

	report_external_interface_down(collection, 2, 2);
	struct scion_path *chosen = select_path(collection, paths[0]);
	assert_ptr_equal(chosen, paths[1]);

	report_external_interface_down(collection, 4, 1);
	assert_ptr_equal(select_path(collection, chosen), paths[2]);
}

static void test_selector_ignores_errors_of_other_paths(void **state)
{
	struct selector_state *s = *state;
	struct scion_path *paths[3];
	struct scion_path_collection *collection = make_three_paths(s, paths);

	// Not a path of the collection, and the wrong AS for the interface
	report_external_interface_down(collection, 7, 1);
	report_external_interface_down(collection, 3, 12);
	// A path that is not in use
	report_external_interface_down(collection, 4, 1);
	assert_ptr_equal(select_path(collection, paths[0]), paths[0]);

	// The path that is down is skipped for a new choice
	report_external_interface_down(collection, 2, 1);
	assert_ptr_equal(select_path(collection, paths[0]), paths[2]);
	assert_ptr_equal(select_path(collection, NULL), paths[2]);
}

static void test_selector_oldest_down_if_all_down(void **state)
{
	struct selector_state *s = *state;
	struct scion_path *paths[3];
	struct scion_path_collection *collection = make_three_paths(s, paths);

	report_external_interface_down(collection, 4, 1);
	report_external_interface_down(collection, 5, 1);
	report_external_interface_down(collection, 2, 1);

	// The clock can be too coarse to tell the errors apart, so set when each path went down
	paths[1]->down_since = 100;
	paths[2]->down_since = 200;
	paths[0]->down_since = 300;
	assert_ptr_equal(select_path(collection, paths[0]), paths[1]);

	// An error that affects a path again does not change when it went down
	report_external_interface_down(collection, 4, 1);
	assert_ptr_equal(select_path(collection, paths[0]), paths[1]);
}

static void test_selector_internal_connectivity_down(void **state)
{
	struct selector_state *s = *state;
	struct scion_path *paths[3];
	struct scion_path_collection *collection = make_three_paths(s, paths);

	struct scion_scmp_error error = { .type = SCION_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN,
		.info.internal_connectivity_down = { .ia = 2, .ingress_interface = 1, .egress_interface = 2 } };
	scion_path_collection_mark_down(collection, &error);

	assert_true(scion_path_is_down(paths[0]));
	assert_false(scion_path_is_down(paths[1]));
	assert_ptr_equal(select_path(collection, paths[0]), paths[1]);
}

static void test_path_is_affected_by_scmp_error(void **state)
{
	struct selector_state *s = *state;
	struct scion_path *paths[3];
	make_three_paths(s, paths);
	struct scion_path *other_interface = MAKE_PATH(via_2_other_interface);
	scion_list_append(s->collections[0]->list, other_interface);

	struct scion_scmp_error external = { .type = SCION_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN,
		.info.external_interface_down = { .ia = 2, .interface = 1 } };
	assert_true(scion_path_is_affected_by_scmp_error(paths[0], &external));
	assert_true(scion_path_is_affected_by_scmp_error(other_interface, &external));
	assert_false(scion_path_is_affected_by_scmp_error(paths[1], &external));

	// The interface 2 belongs to another AS on the other paths
	external.info.external_interface_down.ia = 4;
	external.info.external_interface_down.interface = 2;
	assert_false(scion_path_is_affected_by_scmp_error(paths[0], &external));
	assert_true(scion_path_is_affected_by_scmp_error(paths[1], &external));

	// The path has to pass through the AS between both interfaces, in any direction
	struct scion_scmp_error internal = { .type = SCION_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN,
		.info.internal_connectivity_down = { .ia = 2, .ingress_interface = 1, .egress_interface = 2 } };
	assert_true(scion_path_is_affected_by_scmp_error(paths[0], &internal));
	assert_false(scion_path_is_affected_by_scmp_error(other_interface, &internal));
	internal.info.internal_connectivity_down.ingress_interface = 2;
	internal.info.internal_connectivity_down.egress_interface = 1;
	assert_true(scion_path_is_affected_by_scmp_error(paths[0], &internal));
	internal.info.internal_connectivity_down.ingress_interface = 2;
	internal.info.internal_connectivity_down.egress_interface = 3;
	assert_false(scion_path_is_affected_by_scmp_error(paths[0], &internal));
}

static void test_path_is_not_affected_by_other_errors(void **state)
{
	struct selector_state *s = *state;
	struct scion_path *paths[3];
	make_three_paths(s, paths);

	struct scion_scmp_error error = { .type = SCION_SCMP_TYPE_DESTINATION_UNREACHABLE };
	assert_false(scion_path_is_affected_by_scmp_error(paths[0], &error));

	// A path without metadata, like the empty path
	struct scion_path empty = { .path_type = SCION_PATH_TYPE_EMPTY };
	error.type = SCION_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN;
	assert_false(scion_path_is_affected_by_scmp_error(&empty, &error));
}

static void test_carry_over_keeps_marks_and_current(void **state)
{
	struct selector_state *s = *state;
	struct scion_path *paths[3];
	struct scion_path_collection *old_paths = make_three_paths(s, paths);
	report_external_interface_down(old_paths, 2, 1);

	// The same paths in another order, as new path objects
	struct scion_path *refreshed[3];
	const struct hop *hops[] = { via_5, via_4, via_2 };
	const size_t lens[] = { 4, 4, 4 };
	struct scion_path_collection *new_paths = make_collection(s, refreshed, hops, lens, 3);

	assert_ptr_equal(scion_path_collection_carry_over(new_paths, old_paths, paths[1]), refreshed[1]);
	assert_false(scion_path_is_down(refreshed[0]));
	assert_false(scion_path_is_down(refreshed[1]));
	assert_true(scion_path_is_down(refreshed[2]));
	assert_int_equal(refreshed[2]->down_since, paths[0]->down_since);
}

static void test_carry_over_without_the_current_path(void **state)
{
	struct selector_state *s = *state;
	struct scion_path *paths[3];
	struct scion_path_collection *old_paths = make_three_paths(s, paths);

	// The path in use is not part of the new paths
	struct scion_path *refreshed[2];
	const struct hop *hops[] = { via_2, via_5 };
	const size_t lens[] = { 4, 4 };
	struct scion_path_collection *new_paths = make_collection(s, refreshed, hops, lens, 2);

	assert_null(scion_path_collection_carry_over(new_paths, old_paths, paths[1]));
	assert_null(scion_path_collection_carry_over(new_paths, old_paths, NULL));
	assert_null(scion_path_collection_carry_over(new_paths, NULL, NULL));
}

int run_selector_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_selector_without_paths, setup_selector, teardown_selector),
		cmocka_unit_test_setup_teardown(test_selector_uses_the_first_path, setup_selector, teardown_selector),
		cmocka_unit_test_setup_teardown(test_selector_keeps_the_current_path, setup_selector, teardown_selector),
		cmocka_unit_test_setup_teardown(test_selector_switches_if_current_down, setup_selector, teardown_selector),
		cmocka_unit_test_setup_teardown(test_selector_ignores_errors_of_other_paths, setup_selector, teardown_selector),
		cmocka_unit_test_setup_teardown(test_selector_oldest_down_if_all_down, setup_selector, teardown_selector),
		cmocka_unit_test_setup_teardown(test_selector_internal_connectivity_down, setup_selector, teardown_selector),
		cmocka_unit_test_setup_teardown(test_path_is_affected_by_scmp_error, setup_selector, teardown_selector),
		cmocka_unit_test_setup_teardown(test_path_is_not_affected_by_other_errors, setup_selector, teardown_selector),
		cmocka_unit_test_setup_teardown(test_carry_over_keeps_marks_and_current, setup_selector, teardown_selector),
		cmocka_unit_test_setup_teardown(test_carry_over_without_the_current_path, setup_selector, teardown_selector),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
