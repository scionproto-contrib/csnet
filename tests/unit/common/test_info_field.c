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

#include <cmocka.h>
#include <stdint.h>
#include <string.h>

#include "common/info_field.h"
#include "test_info_field.h"

static void test_serialize_info_field(void **)
{
	struct scion_info_field info_field;
	info_field.peer = false;
	info_field.cons_dir = true;
	info_field.seg_id = 0x3bfa;
	info_field.timestamp = 1731596031;

	uint8_t buf[8];
	scion_info_field_serialize((uint8_t *)&buf, &info_field);

	const uint8_t test_buf[] = {
		0x01,
		0x00,
		0x3b,
		0xfa,
		0x67,
		0x36,
		0x0e,
		0xff,
	};

	assert_memory_equal(buf, test_buf, sizeof(buf));
}

static void test_deserialize_info_field(void **)
{
	struct scion_info_field info_field;

	const uint8_t buf[] = {
		0x01,
		0x00,
		0x3b,
		0xfa,
		0x67,
		0x36,
		0x0e,
		0xff,
	};

	assert_int_equal(scion_info_field_deserialize((uint8_t *)&buf, &info_field), 0);

	assert_false(info_field.peer);
	assert_true(info_field.cons_dir);
	assert_uint_equal(info_field.seg_id, 0x3bfa);
	assert_uint_equal(info_field.timestamp, 1731596031);
}

static void test_info_field_flags(void **)
{
	const struct {
		bool peer;
		bool cons_dir;
		uint8_t flags;
	} cases[] = { { false, false, 0x00 }, { false, true, 0x01 }, { true, false, 0x02 }, { true, true, 0x03 } };

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		struct scion_info_field info_field = { .peer = cases[i].peer, .cons_dir = cases[i].cons_dir };

		uint8_t buf[SCION_INFO_LEN];
		scion_info_field_serialize(buf, &info_field);
		assert_uint_equal(buf[0], cases[i].flags);

		struct scion_info_field parsed;
		scion_info_field_deserialize(buf, &parsed);
		assert_int_equal(parsed.peer, cases[i].peer);
		assert_int_equal(parsed.cons_dir, cases[i].cons_dir);
	}
}

static void test_info_field_round_trip_extremes(void **)
{
	struct scion_info_field info_field
		= { .peer = true, .cons_dir = true, .seg_id = UINT16_MAX, .timestamp = UINT32_MAX };

	uint8_t buf[SCION_INFO_LEN];
	scion_info_field_serialize(buf, &info_field);

	struct scion_info_field parsed;
	scion_info_field_deserialize(buf, &parsed);
	assert_uint_equal(parsed.seg_id, UINT16_MAX);
	assert_uint_equal(parsed.timestamp, UINT32_MAX);
}

static void test_deserialize_info_field_ignores_reserved_bits(void **)
{
	const uint8_t buf[] = { 0xfc, 0xff, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02 };

	struct scion_info_field parsed;
	scion_info_field_deserialize(buf, &parsed);
	assert_false(parsed.peer);
	assert_false(parsed.cons_dir);
	assert_uint_equal(parsed.seg_id, 1);
	assert_uint_equal(parsed.timestamp, 2);
}

int run_info_field_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_serialize_info_field),
		cmocka_unit_test(test_deserialize_info_field),
		cmocka_unit_test(test_info_field_flags),
		cmocka_unit_test(test_info_field_round_trip_extremes),
		cmocka_unit_test(test_deserialize_info_field_ignores_reserved_bits),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
