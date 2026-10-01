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

#include "common/as_entry.h"
#include "control_plane/path_metadata.h"
#include "scion/scion.h"
#include "test_path_metadata.h"
#include "util/list.h"
#include "util/map.h"

// Everything a test allocates, so teardown_fixture can free it even if an assertion fails partway through the test.
struct path_metadata_test_fixture {
	struct scion_list *interfaces;
	struct scion_list *as_entries;
	struct scion_path_metadata *metadata;
};

static int teardown_fixture(void **state)
{
	struct path_metadata_test_fixture *fixture = *state;
	if (fixture == NULL) {
		return 0;
	}
	scion_path_metadata_free(fixture->metadata);
	scion_list_free(fixture->as_entries);
	scion_list_free(fixture->interfaces);
	free(fixture);
	return 0;
}

static scion_ia parse_ia(const char *str)
{
	scion_ia ia;
	assert_int_equal(scion_ia_parse(str, strlen(str), &ia), 0);
	return ia;
}

static void add_interface(struct scion_list *interfaces, scion_ia ia, scion_ifid id)
{
	struct scion_path_interface *intf = malloc(sizeof(*intf));
	intf->ia = ia;
	intf->id = id;
	scion_list_append(interfaces, intf);
}

// An AS entry with no static info extension.
static struct scion_as_entry *make_as_entry(scion_ia local, scion_ifid cons_egress)
{
	struct scion_as_entry *entry = calloc(1, sizeof(*entry));
	entry->local = local;
	entry->hop_entry.hop_field.cons_egress = cons_egress;
	entry->mtu = 1400;
	return entry;
}

static struct scion_map *make_u16_map(void)
{
	return scion_map_create((struct scion_map_key_config){ .size = sizeof(uint16_t), .serialize = NULL },
		SCION_MAP_SIMPLE_FREE);
}

static struct scion_map *make_ifid_map(void)
{
	return scion_map_create((struct scion_map_key_config){ .size = sizeof(scion_ifid), .serialize = NULL },
		SCION_MAP_SIMPLE_FREE);
}

static void test_path_metadata_minimal(void **state)
{
	struct path_metadata_test_fixture *fixture = calloc(1, sizeof(*fixture));
	*state = fixture;

	scion_ia as1 = parse_ia("1-ff00:0:110");
	scion_ia as2 = parse_ia("1-ff00:0:111");
	scion_ia as3 = parse_ia("1-ff00:0:112");

	fixture->interfaces = scion_list_create(SCION_LIST_SIMPLE_FREE);
	add_interface(fixture->interfaces, as1, 100);
	add_interface(fixture->interfaces, as2, 101);
	add_interface(fixture->interfaces, as2, 102);
	add_interface(fixture->interfaces, as3, 103);

	fixture->as_entries = scion_list_create(SCION_LIST_CUSTOM_FREE(scion_as_entry_free));
	scion_list_append(fixture->as_entries, make_as_entry(as1, 100));
	scion_list_append(fixture->as_entries, make_as_entry(as2, 102));
	scion_list_append(fixture->as_entries, make_as_entry(as3, 0));

	fixture->metadata = scion_path_metadata_collect(fixture->interfaces, fixture->as_entries, 1400, 1700000000);

	assert_int_equal(fixture->metadata->mtu, 1400);
	assert_int_equal(fixture->metadata->expiry, 1700000000);

	assert_int_equal(fixture->metadata->interfaces_len, 4);
	assert_true(fixture->metadata->interfaces[0].ia == as1 && fixture->metadata->interfaces[0].id == 100);
	assert_true(fixture->metadata->interfaces[3].ia == as3 && fixture->metadata->interfaces[3].id == 103);

	assert_int_equal(fixture->metadata->ases_len, 3);
	assert_true(fixture->metadata->ases[0] == as1);
	assert_true(fixture->metadata->ases[1] == as2);
	assert_true(fixture->metadata->ases[2] == as3);

	// No AS entry has a static info extension, so every collected value reports "unset".
	for (size_t i = 0; i < fixture->metadata->interfaces_len - 1; i++) {
		assert_true(SCION_PATH_METADATA_LATENCY_IS_UNSET(fixture->metadata->latencies[i]));
		assert_true(SCION_PATH_METADATA_BANDWIDTH_IS_UNSET(fixture->metadata->bandwidths[i]));
	}
	for (size_t i = 0; i < fixture->metadata->interfaces_len / 2; i++) {
		assert_int_equal(fixture->metadata->link_types[i], SCION_LINK_TYPE_UNSPECIFIED);
	}
	assert_int_equal(fixture->metadata->internal_hops[0], 0);
	for (size_t i = 0; i < fixture->metadata->ases_len; i++) {
		assert_int_equal(strlen(fixture->metadata->notes[i]), 0);
	}
}

// AS2 (the middle AS, spanning interfaces[1..2]) sets latency, bandwidth, geo, link type, internal hops, and a
// note. Verify each ends up at the right index, and everywhere else stays unset.
//
//   interfaces:   [0]100      [1]101   [2]102      [3]103
//                  AS1 <------------>   <------------> AS3
//                            AS2 (101 ingress, 102 egress)
//
//   link_types[0] = 100-101 (AS1-AS2)     link_types[1] = 102-103 (AS2-AS3)
//   internal_hops[0] = 101-102 (within AS2, where latency/bandwidth are set too)
static void test_path_metadata_static_info(void **state)
{
	struct path_metadata_test_fixture *fixture = calloc(1, sizeof(*fixture));
	*state = fixture;

	scion_ia as1 = parse_ia("1-ff00:0:110");
	scion_ia as2 = parse_ia("1-ff00:0:111");
	scion_ia as3 = parse_ia("1-ff00:0:112");

	fixture->interfaces = scion_list_create(SCION_LIST_SIMPLE_FREE);
	add_interface(fixture->interfaces, as1, 100);
	add_interface(fixture->interfaces, as2, 101);
	add_interface(fixture->interfaces, as2, 102);
	add_interface(fixture->interfaces, as3, 103);

	struct scion_as_entry *as2_entry = make_as_entry(as2, 102);
	struct scion_static_info_extension *si = calloc(1, sizeof(*si));
	as2_entry->extensions.static_info = si;

	// Latency/bandwidth/internal_hops between AS2's own ingress (101) and egress (102) interfaces: keyed by the
	// "other" (ingress) interface.
	uint16_t ingress_ifid = 101;

	si->latency = malloc(sizeof(*si->latency));
	si->latency->intra = make_u16_map();
	si->latency->inter = make_u16_map();
	struct timeval *latency = malloc(sizeof(*latency));
	*latency = (struct timeval){ .tv_sec = 0, .tv_usec = 5000 };
	scion_map_put(si->latency->intra, &ingress_ifid, latency);

	si->bandwidth = malloc(sizeof(*si->bandwidth));
	si->bandwidth->intra = make_u16_map();
	si->bandwidth->inter = make_u16_map();
	uint64_t *bandwidth = malloc(sizeof(*bandwidth));
	*bandwidth = 1000;
	scion_map_put(si->bandwidth->intra, &ingress_ifid, bandwidth);

	si->internal_hops = make_u16_map();
	uint32_t *internal_hops = malloc(sizeof(*internal_hops));
	*internal_hops = 3;
	scion_map_put(si->internal_hops, &ingress_ifid, internal_hops);

	// Geo is keyed by the interface's own id: report it for AS2's egress interface (102). Unlike the others, its
	// key is a scion_ifid, not a uint16_t - scion_path_metadata_collect() reads it back as one.
	si->geo = make_ifid_map();
	struct scion_geo_coordinates *geo = malloc(sizeof(*geo));
	*geo = (struct scion_geo_coordinates){ .latitude = 47.37f, .longitude = 8.55f, .address = NULL };
	scion_ifid egress_ifid = 102;
	scion_map_put(si->geo, &egress_ifid, geo);

	// Link type is keyed by the interface's own id too, and resolved against its AS1-facing partner (100) to fill
	// link_types[0].
	si->link_type = make_u16_map();
	enum scion_link_type *link_type = malloc(sizeof(*link_type));
	*link_type = SCION_LINK_TYPE_DIRECT;
	scion_map_put(si->link_type, &ingress_ifid, link_type);

	si->note = strdup("hello from AS2");

	fixture->as_entries = scion_list_create(SCION_LIST_CUSTOM_FREE(scion_as_entry_free));
	scion_list_append(fixture->as_entries, make_as_entry(as1, 100));
	scion_list_append(fixture->as_entries, as2_entry);
	scion_list_append(fixture->as_entries, make_as_entry(as3, 0));

	fixture->metadata = scion_path_metadata_collect(fixture->interfaces, fixture->as_entries, 1400, 1700000000);

	// Only AS2's intra latency (keyed by its ingress ifid 101) was set above, which covers the AS2-internal
	// 101-102 hop, i.e. latencies[1]. AS1 and AS3 set nothing, so latencies[0] (AS1-AS2) and latencies[2]
	// (AS2-AS3) stay unset.
	assert_true(SCION_PATH_METADATA_LATENCY_IS_UNSET(fixture->metadata->latencies[0]));
	assert_false(SCION_PATH_METADATA_LATENCY_IS_UNSET(fixture->metadata->latencies[1]));
	assert_int_equal(fixture->metadata->latencies[1].tv_usec, 5000);
	assert_true(SCION_PATH_METADATA_LATENCY_IS_UNSET(fixture->metadata->latencies[2]));

	assert_true(SCION_PATH_METADATA_BANDWIDTH_IS_UNSET(fixture->metadata->bandwidths[0]));
	assert_int_equal(fixture->metadata->bandwidths[1], 1000);
	assert_true(SCION_PATH_METADATA_BANDWIDTH_IS_UNSET(fixture->metadata->bandwidths[2]));

	assert_int_equal(fixture->metadata->internal_hops[0], 3);

	assert_int_equal(fixture->metadata->geo[2].latitude, 47.37f);
	assert_int_equal(fixture->metadata->geo[2].longitude, 8.55f);
	assert_true(SCION_PATH_METADATA_GEO_IS_UNSET(fixture->metadata->geo[0]));

	assert_int_equal(fixture->metadata->link_types[0], SCION_LINK_TYPE_DIRECT);
	assert_int_equal(fixture->metadata->link_types[1], SCION_LINK_TYPE_UNSPECIFIED);

	assert_string_equal(fixture->metadata->notes[1], "hello from AS2");
	assert_int_equal(strlen(fixture->metadata->notes[0]), 0);
}

// A duplicate note from the same AS is not repeated, but distinct notes from the same AS are joined with a newline.
static void test_path_metadata_notes_merge_and_dedup(void **state)
{
	struct path_metadata_test_fixture *fixture = calloc(1, sizeof(*fixture));
	*state = fixture;

	scion_ia as1 = parse_ia("1-ff00:0:110");
	scion_ia as2 = parse_ia("1-ff00:0:111");

	fixture->interfaces = scion_list_create(SCION_LIST_SIMPLE_FREE);
	add_interface(fixture->interfaces, as1, 10);
	add_interface(fixture->interfaces, as2, 11);

	fixture->as_entries = scion_list_create(SCION_LIST_CUSTOM_FREE(scion_as_entry_free));

	struct scion_as_entry *foo = make_as_entry(as1, 10);
	foo->extensions.static_info = calloc(1, sizeof(*foo->extensions.static_info));
	foo->extensions.static_info->note = strdup("foo");
	scion_list_append(fixture->as_entries, foo);

	struct scion_as_entry *foo_dup = make_as_entry(as1, 10);
	foo_dup->extensions.static_info = calloc(1, sizeof(*foo_dup->extensions.static_info));
	foo_dup->extensions.static_info->note = strdup("foo");
	scion_list_append(fixture->as_entries, foo_dup);

	struct scion_as_entry *bar = make_as_entry(as1, 10);
	bar->extensions.static_info = calloc(1, sizeof(*bar->extensions.static_info));
	bar->extensions.static_info->note = strdup("bar");
	scion_list_append(fixture->as_entries, bar);

	fixture->metadata = scion_path_metadata_collect(fixture->interfaces, fixture->as_entries, 1400, 1700000000);

	assert_string_equal(fixture->metadata->notes[0], "foo\nbar");
	assert_int_equal(strlen(fixture->metadata->notes[1]), 0);
}

int run_path_metadata_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_teardown(test_path_metadata_minimal, teardown_fixture),
		cmocka_unit_test_teardown(test_path_metadata_static_info, teardown_fixture),
		cmocka_unit_test_teardown(test_path_metadata_notes_merge_and_dedup, teardown_fixture),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
