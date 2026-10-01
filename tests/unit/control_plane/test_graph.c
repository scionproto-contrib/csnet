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
#include <string.h>
#include <sys/socket.h>

#include "common/isd_as.h"
#include "common/path_segment.h"
#include "control_plane/graph.h"
#include "control_plane/topology.h"
#include "data_plane/path.h"
#include "scion/scion.h"
#include "test_graph.h"
#include "util/list.h"

// Everything a test allocates, so teardown_graph_fixture can free it even if an assertion fails partway through
// the test.
struct graph_test_fixture {
	struct scion_topology *topo;
	struct scion_path_segment *segment;
	struct scion_list *paths;
};

static int teardown_graph_fixture(void **state)
{
	struct graph_test_fixture *fixture = *state;
	if (fixture == NULL) {
		return 0;
	}
	scion_list_free(fixture->paths);
	scion_path_segment_free(fixture->segment);
	scion_topology_free(fixture->topo);
	free(fixture);
	return 0;
}

static scion_ia parse_ia(const char *str)
{
	scion_ia ia;
	assert_int_equal(scion_ia_parse(str, strlen(str), &ia), 0);
	return ia;
}

static void free_test_border_router(void *value)
{
	struct scion_border_router *br = value;
	free(br->ifids);
	free(br);
}

// A topology with a single border router reachable via ifid.
static struct scion_topology *make_topology(scion_ia local_ia, scion_ifid ifid)
{
	struct scion_topology *topo = calloc(1, sizeof(*topo));
	topo->ia = local_ia;
	topo->local_addr_family = SCION_AF_INET;
	topo->border_routers = scion_list_create(SCION_LIST_CUSTOM_FREE(free_test_border_router));

	struct scion_border_router *br = calloc(1, sizeof(*br));
	br->ifids = malloc(sizeof(*br->ifids));
	br->ifids[0] = ifid;
	br->ifid_len = 1;
	br->addr.ss_family = AF_INET;
	br->addr_len = sizeof(br->addr);
	scion_list_append(topo->border_routers, br);

	return topo;
}

static struct scion_as_entry *make_as_entry(scion_ia local, uint16_t cons_ingress, uint16_t cons_egress)
{
	struct scion_as_entry *entry = calloc(1, sizeof(*entry));
	entry->local = local;
	entry->hop_entry.hop_field.cons_ingress = cons_ingress;
	entry->hop_entry.hop_field.cons_egress = cons_egress;
	entry->hop_entry.hop_field.exp_time = 63;
	entry->hop_entry.ingress_mtu = 1400;
	entry->mtu = 1400;
	return entry;
}

// A CORE segment directly connecting src to dst. scion_build_paths() internally builds the edge from the last
// as_entries slot to the first, so src goes at index 1 and dst at index 0.
static struct scion_path_segment *make_direct_core_segment(scion_ia src, scion_ia dst, scion_ifid ifid)
{
	struct scion_as_entry **as_entries = malloc(2 * sizeof(*as_entries));
	as_entries[1] = make_as_entry(src, 0, ifid);
	as_entries[0] = make_as_entry(dst, ifid, 0);

	struct scion_path_segment *seg = calloc(1, sizeof(*seg));
	seg->info.timestamp = 1700000000;
	seg->info.segment_id = 1;
	seg->as_entries = as_entries;
	seg->as_entries_length = 2;
	return seg;
}

static void test_graph_direct_core_path(void **state)
{
	struct graph_test_fixture *fixture = calloc(1, sizeof(*fixture));
	*state = fixture;

	scion_ia src = parse_ia("1-ff00:0:110");
	scion_ia dst = parse_ia("1-ff00:0:111");
	scion_ifid ifid = 100;

	fixture->topo = make_topology(src, ifid);
	fixture->segment = make_direct_core_segment(src, dst, ifid);
	fixture->paths = scion_list_create(SCION_LIST_CUSTOM_FREE(scion_path_free));

	int ret = scion_build_paths(src, dst, fixture->topo, NULL, 0, &fixture->segment, 1, NULL, 0, fixture->paths, 0);

	assert_int_equal(ret, 0);
	assert_uint_equal(scion_list_size(fixture->paths), 1);

	struct scion_path *path = fixture->paths->first->value;
	assert_true(path->src == src);
	assert_true(path->dst == dst);
	assert_int_equal(path->path_type, SCION_PATH_TYPE_SCION);
	assert_int_equal(path->weight, 1);
	assert_int_equal(path->metadata->interfaces_len, 2);
}

// Regression test: hop fields with no interface IDs used to crash with a NULL deref. Such a path is now rejected,
// like any other search that yields no usable path.
static void test_graph_all_zero_hop_fields(void **state)
{
	struct graph_test_fixture *fixture = calloc(1, sizeof(*fixture));
	*state = fixture;

	scion_ia src = parse_ia("1-ff00:0:110");
	scion_ia dst = parse_ia("1-ff00:0:111");

	fixture->topo = make_topology(src, 100);
	fixture->segment = make_direct_core_segment(src, dst, 0);
	fixture->paths = scion_list_create(SCION_LIST_CUSTOM_FREE(scion_path_free));

	int ret = scion_build_paths(src, dst, fixture->topo, NULL, 0, &fixture->segment, 1, NULL, 0, fixture->paths, 0);

	assert_int_equal(ret, SCION_ERR_NO_PATHS);
	assert_uint_equal(scion_list_size(fixture->paths), 0);
}

// With no segments at all, src never appears in the graph, so the whole call fails with SCION_ERR_NO_PATHS rather
// than just yielding an empty path list.
static void test_graph_no_segments(void **state)
{
	struct graph_test_fixture *fixture = calloc(1, sizeof(*fixture));
	*state = fixture;

	scion_ia src = parse_ia("1-ff00:0:110");
	scion_ia dst = parse_ia("1-ff00:0:111");

	fixture->topo = make_topology(src, 100);
	fixture->paths = scion_list_create(SCION_LIST_CUSTOM_FREE(scion_path_free));

	int ret = scion_build_paths(src, dst, fixture->topo, NULL, 0, NULL, 0, NULL, 0, fixture->paths, 0);

	assert_int_equal(ret, SCION_ERR_NO_PATHS);
	assert_uint_equal(scion_list_size(fixture->paths), 0);
}

int run_graph_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_teardown(test_graph_direct_core_path, teardown_graph_fixture),
		cmocka_unit_test_teardown(test_graph_all_zero_hop_fields, teardown_graph_fixture),
		cmocka_unit_test_teardown(test_graph_no_segments, teardown_graph_fixture),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
