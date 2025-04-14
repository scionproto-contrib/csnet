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
#include "util/test_linked_list.h"

static void run_test(int (*f)(void), const char *s, int *total, int *success, int *fail)
{
	int ret = (*f)();
	*total += 1;

	if (ret == 0) {
		printf("[%s]: SUCCESS\n", s);
		*success += 1;
	} else {
		printf("[%s]: FAIL with return value: %i\n", s, ret);
		*fail += 1;
	}
	return;
}

static void new_category(
	const char *name, int *tests, int *success, int *fail, int *total, int *success_total, int *fail_total)
{
	if (*tests > 0) {
		printf("Completed %i tests, %i were successful, %i failed.\n", *tests, *success, *fail);
		*total += *tests;
		*success_total += *success;
		*fail_total += *fail;
	}
	*tests = 0;
	*success = 0;
	*fail = 0;
	printf("\nTests for %s\n", name);
	return;
}

static void finish_tests(int *tests, int *success, int *fail, int *total, int *success_total, int *fail_total)
{
	if (*tests > 0) {
		printf("Completed %i tests, %i were successful, %i failed.\n", *tests, *success, *fail);
		*total += *tests;
		*success_total += *success;
		*fail_total += *fail;
	}
	printf("\nTotal results:\n");
	printf("Completed %i tests, %i were successful, %i failed.\n", *total, *success_total, *fail_total);
	return;
}

void scion_run_tests(void)
{
	int tests = 0;
	int success = 0;
	int fail = 0;
	int total = 0;
	int success_total = 0;
	int fail_total = 0;

	printf("\nRunning tests...\n");

	// LinkedList tests
	new_category("ScionLinkedList", &tests, &success, &fail, &total, &success_total, &fail_total);
	run_test(&scion_test_list_create, "scion_test_list_create", &tests, &success, &fail);
	run_test(&scion_test_list_append, "scion_test_list_append", &tests, &success, &fail);
	run_test(&scion_test_list_append_all, "scion_test_list_append_all", &tests, &success, &fail);
	run_test(&scion_test_list_append_all_null, "scion_test_list_append_all_null", &tests, &success, &fail);
	run_test(&scion_test_list_pop, "scion_test_list_pop", &tests, &success, &fail);
	run_test(&scion_test_list_reverse, "scion_test_list_reverse", &tests, &success, &fail);
	run_test(&scion_test_list_free, "scion_test_list_free", &tests, &success, &fail);
	run_test(&scion_test_list_free_value, "scion_test_list_free_value", &tests, &success, &fail);
	run_test(&scion_test_list_free_value_custom, "scion_test_list_free_value_custom", &tests, &success, &fail);

	// ISD-AS tests
	new_category("ISD-AS", &tests, &success, &fail, &total, &success_total, &fail_total);
	run_test(&scion_test_ia_from_isd_as, "scion_test_ia_from_isd_as", &tests, &success, &fail);
	run_test(
		&scion_test_ia_from_isd_as_too_large_as, "scion_test_ia_from_isd_as_too_large_as", &tests, &success, &fail);
	run_test(&scion_test_get_isd, "scion_test_get_isd", &tests, &success, &fail);
	run_test(&scion_test_get_as, "scion_test_get_as", &tests, &success, &fail);
	run_test(&scion_test_to_wildcard, "scion_test_to_wildcard", &tests, &success, &fail);
	run_test(&scion_test_is_wildcard, "scion_test_is_wildcard", &tests, &success, &fail);
	run_test(&scion_test_parse_ia, "scion_test_parse_ia", &tests, &success, &fail);

	new_category("Serialization", &tests, &success, &fail, &total, &success_total, &fail_total);
	run_test(&scion_test_serialize_udp, "scion_test_serialize_udp", &tests, &success, &fail);
	run_test(&scion_test_serialize_meta_hdr, "scion_test_serialize_meta_hdr", &tests, &success, &fail);
	run_test(&scion_test_serialize_info_field, "scion_test_serialize_info_field", &tests, &success, &fail);
	run_test(&scion_test_serialize_hop_field, "scion_test_serialize_hop_field", &tests, &success, &fail);
	run_test(&scion_test_serialize_path, "scion_test_serialize_path", &tests, &success, &fail);
	run_test(&scion_test_serialize_scion_packet, "scion_test_serialize_scion_packet", &tests, &success, &fail);
	run_test(&scion_test_serialize_scmp_echo, "scion_test_serialize_scmp_echo", &tests, &success, &fail);

	new_category("Deserialization", &tests, &success, &fail, &total, &success_total, &fail_total);
	run_test(&scion_test_deserialize_udp, "scion_test_deserialize_udp", &tests, &success, &fail);
	run_test(&scion_test_deserialize_meta_hdr, "scion_test_deserialize_meta_hdr", &tests, &success, &fail);
	run_test(&scion_test_deserialize_info_field, "scion_test_deserialize_info_field", &tests, &success, &fail);
	run_test(&scion_test_deserialize_hop_field, "scion_test_deserialize_hop_field", &tests, &success, &fail);
	run_test(&scion_test_deserialize_path, "scion_test_deserialize_path", &tests, &success, &fail);
	run_test(&scion_test_deserialize_scion_packet, "scion_test_deserialize_scion_packet", &tests, &success, &fail);

	new_category("Path", &tests, &success, &fail, &total, &success_total, &fail_total);
	run_test(&scion_test_init_raw_path, "scion_test_init_raw_path", &tests, &success, &fail);
	run_test(&scion_test_reverse_path, "scion_test_reverse_path", &tests, &success, &fail);

	finish_tests(&tests, &success, &fail, &total, &success_total, &fail_total);
	return;
}

int main(int argc, char *argv[])
{
	scion_run_tests();
}
