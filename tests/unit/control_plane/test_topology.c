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
#include <stdio.h>
#include <string.h>

#include "common/isd_as.h"
#include "control_plane/topology.h"
#include "data_plane/underlay.h"
#include "scion/scion.h"
#include "test_topology.h"

static void testdata_path(char *buf, size_t buf_len, const char *filename)
{
	snprintf(buf, buf_len, "%s/%s", TEST_TOPOLOGY_DATA_DIR, filename);
}

static struct scion_topology *load_topology(const char *filename)
{
	char path[512];
	testdata_path(path, sizeof(path), filename);

	struct scion_topology *topo = NULL;
	int ret = scion_topology_from_file(&topo, path);
	assert_int_equal(ret, 0);
	assert_non_null(topo);
	return topo;
}

static int teardown_topology(void **state)
{
	scion_topology_free(*state);
	return 0;
}

static void assert_load_rejected(const char *filename)
{
	char path[512];
	testdata_path(path, sizeof(path), filename);

	struct scion_topology *topo = NULL;
	int ret = scion_topology_from_file(&topo, path);
	assert_int_equal(ret, SCION_ERR_TOPOLOGY_INVALID);
	assert_null(topo);
}

static scion_ia parse_ia(const char *str)
{
	scion_ia ia;
	assert_int_equal(scion_ia_parse(str, strlen(str), &ia), 0);
	return ia;
}

static void test_topology_minimal(void **state)
{
	struct scion_topology *topo = load_topology("minimal.json");
	*state = topo;

	assert_true(scion_topology_get_local_ia(topo) == parse_ia("1-ff00:0:111"));
	assert_false(scion_topology_is_local_as_core(topo));
	assert_uint_equal(scion_list_size(topo->border_routers), 1);

	struct scion_underlay underlay;
	assert_int_equal(scion_topology_next_underlay_hop(topo, 1, &underlay), 0);
	assert_int_equal(scion_topology_next_underlay_hop(topo, SCION_INTERFACE_ANY, &underlay), 0);
	assert_int_equal(scion_topology_next_underlay_hop(topo, 99, &underlay), SCION_ERR_TOPOLOGY_INVALID);
}

static void test_topology_core_as(void **state)
{
	struct scion_topology *topo = load_topology("core_as.json");
	*state = topo;

	assert_true(scion_topology_is_local_as_core(topo));
}

static void test_topology_ipv6_addresses(void **state)
{
	struct scion_topology *topo = load_topology("ipv6.json");
	*state = topo;

	struct scion_underlay underlay;
	assert_int_equal(scion_topology_next_underlay_hop(topo, 7, &underlay), 0);
	assert_int_equal(underlay.addr_family, SCION_AF_INET6);
}

// local_addr_family is derived from the control service address, not from any border router - this holds even
// when a border router has a different address family than the control service.
static void test_topology_address_family_comes_from_control_service(void **state)
{
	struct scion_topology *topo = load_topology("mixed_address_family.json");
	*state = topo;

	assert_int_equal(topo->local_addr_family, SCION_AF_INET);
}

static void test_topology_missing_isd_as_is_rejected(void **)
{
	assert_load_rejected("missing_isd_as.json");
}

static void test_topology_missing_control_service_is_rejected(void **)
{
	assert_load_rejected("missing_control_service.json");
}

static void test_topology_missing_border_routers_is_rejected(void **)
{
	assert_load_rejected("missing_border_routers.json");
}

static void test_topology_malformed_isd_as_is_rejected(void **)
{
	assert_load_rejected("malformed_isd_as.json");
}

static void test_topology_malformed_control_service_address_is_rejected(void **)
{
	assert_load_rejected("malformed_control_service_address.json");
}

static void test_topology_malformed_border_router_address_is_rejected(void **)
{
	assert_load_rejected("malformed_border_router_address.json");
}

static void test_topology_top_level_non_object_is_rejected(void **)
{
	assert_load_rejected("not_a_json_object.json");
}

static void test_topology_invalid_json_is_rejected(void **)
{
	assert_load_rejected("invalid_json.json");
}

static void test_topology_empty_file_is_rejected(void **)
{
	assert_load_rejected("empty.json");
}

static void test_topology_nonexistent_file_is_rejected(void **)
{
	struct scion_topology *topo = NULL;
	int ret = scion_topology_from_file(&topo, "/nonexistent/path/topology.json");
	assert_int_equal(ret, SCION_ERR_FILE_NOT_FOUND);
	assert_null(topo);
}

// Regression test for a bug where scion_topology_from_file only kept the first interface of each border router.
// multiple_interfaces_per_border_router.json has two interfaces per border router (104+101, 105+103, 100+102);
// all six must be reachable via scion_topology_next_underlay_hop.
static void test_topology_multiple_interfaces_per_border_router(void **state)
{
	struct scion_topology *topo = load_topology("multiple_interfaces_per_border_router.json");
	*state = topo;

	const scion_ifid all_ifids[] = { 104, 101, 105, 103, 100, 102 };
	for (size_t i = 0; i < sizeof(all_ifids) / sizeof(all_ifids[0]); i++) {
		struct scion_underlay underlay;
		int hop_ret = scion_topology_next_underlay_hop(topo, all_ifids[i], &underlay);
		assert_int_equal(hop_ret, 0);
	}
}

static void test_topology_missing_interfaces_is_rejected(void **)
{
	assert_load_rejected("missing_interfaces.json");
}

int run_topology_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_teardown(test_topology_minimal, teardown_topology),
		cmocka_unit_test_teardown(test_topology_core_as, teardown_topology),
		cmocka_unit_test_teardown(test_topology_ipv6_addresses, teardown_topology),
		cmocka_unit_test_teardown(test_topology_address_family_comes_from_control_service, teardown_topology),
		cmocka_unit_test(test_topology_missing_isd_as_is_rejected),
		cmocka_unit_test(test_topology_missing_control_service_is_rejected),
		cmocka_unit_test(test_topology_missing_border_routers_is_rejected),
		cmocka_unit_test(test_topology_malformed_isd_as_is_rejected),
		cmocka_unit_test(test_topology_malformed_control_service_address_is_rejected),
		cmocka_unit_test(test_topology_malformed_border_router_address_is_rejected),
		cmocka_unit_test(test_topology_top_level_non_object_is_rejected),
		cmocka_unit_test(test_topology_invalid_json_is_rejected),
		cmocka_unit_test(test_topology_empty_file_is_rejected),
		cmocka_unit_test(test_topology_nonexistent_file_is_rejected),
		cmocka_unit_test_teardown(test_topology_multiple_interfaces_per_border_router, teardown_topology),
		cmocka_unit_test(test_topology_missing_interfaces_is_rejected),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
