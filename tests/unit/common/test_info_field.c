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

int run_info_field_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_serialize_info_field),
		cmocka_unit_test(test_deserialize_info_field),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
