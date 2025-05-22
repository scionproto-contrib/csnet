// Copyright 2024 ETH Zurich
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

#include <stdio.h>

#include "common/test_isd_as.h"
#include "data_plane/test_deserialization.h"
#include "data_plane/test_path.h"
#include "data_plane/test_serialization.h"
#include "testing.h"
#include "util/test_list.h"
#include "util/test_map.h"

#include <assert.h>
#include <string.h>

struct test {
	const char *name;
	int (*func)(void);
};

static struct test tests[] = { { .name = "list_create", .func = scion_test_list_create },
	{ .name = "list_append", .func = scion_test_list_append },
	{ .name = "list_append_all", .func = scion_test_list_append_all },
	{ .name = "list_append_all_null", .func = scion_test_list_append_all_null },
	{ .name = "list_pop", .func = scion_test_list_pop }, { .name = "list_reverse", .func = scion_test_list_reverse },
	{ .name = "list_free", .func = scion_test_list_free },
	{ .name = "list_free_value", .func = scion_test_list_free_value },
	{ .name = "list_free_value_custom", .func = scion_test_list_free_value_custom },
	{ .name = "ia_from_isd_as", .func = scion_test_ia_from_isd_as },
	{ .name = "ia_from_isd_as_too_large_as", .func = scion_test_ia_from_isd_as_too_large_as },
	{ .name = "get_isd", .func = scion_test_get_isd }, { .name = "get_as", .func = scion_test_get_as },
	{ .name = "to_wildcard", .func = scion_test_to_wildcard },
	{ .name = "is_wildcard", .func = scion_test_is_wildcard }, { .name = "parse_ia", .func = scion_test_parse_ia },
	{ .name = "serialize_udp", .func = scion_test_serialize_udp },
	{ .name = "serialize_meta_hdr", .func = scion_test_serialize_meta_hdr },
	{ .name = "serialize_info_field", .func = scion_test_serialize_info_field },
	{ .name = "serialize_hop_field", .func = scion_test_serialize_hop_field },
	{ .name = "serialize_path", .func = scion_test_serialize_path },
	{ .name = "serialize_scion_packet", .func = scion_test_serialize_scion_packet },
	{ .name = "serialize_scmp_echo", .func = scion_test_serialize_scmp_echo },
	{ .name = "deserialize_udp", .func = scion_test_deserialize_udp },
	{ .name = "deserialize_meta_hdr", .func = scion_test_deserialize_meta_hdr },
	{ .name = "deserialize_info_field", .func = scion_test_deserialize_info_field },
	{ .name = "deserialize_hop_field", .func = scion_test_deserialize_hop_field },
	{ .name = "deserialize_path", .func = scion_test_deserialize_path },
	{ .name = "deserialize_scion_packet", .func = scion_test_deserialize_scion_packet },
	{ .name = "init_raw_path", .func = scion_test_init_raw_path },
	{ .name = "reverse_path", .func = scion_test_reverse_path },
	{ .name = "map_example", .func = scion_test_map_example } };

int main(int argc, char *argv[])
{
	for (size_t i = 0; i < sizeof(tests); i++) {
		if (strcmp(tests[i].name, argv[1]) == 0) {
			return tests[i].func();
		}
	}

	(void)fprintf(stderr, "test not found\n");
	return 1;
}
