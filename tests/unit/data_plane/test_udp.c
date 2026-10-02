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
#include <stdlib.h>

#include "data_plane/udp.h"
#include "test_udp.h"

static void test_serialize_udp(void **)
{
	struct scion_udp udp;
	udp.src_port = 31337;
	udp.dst_port = 31000;
	udp.data_length = 0;
	udp.data = NULL;

	uint16_t buf_len = 8;
	uint8_t buf[buf_len];
	assert_int_equal(scion_udp_serialize(&udp, buf, &buf_len), 0);

	const uint8_t test_buf[] = {
		0x7a,
		0x69,
		0x79,
		0x18,
		0x00,
		0x08,
		0x00,
		0x00,
	};

	assert_memory_equal(buf, test_buf, sizeof(buf));
}

static void test_deserialize_udp(void **)
{
	struct scion_udp udp;

	const uint8_t buf[] = {
		0x7a, // 31337 = 0x7a69
		0x69,
		0x79, // 31000 = 0x7918
		0x18,
		0x00,
		0x08,
		0x00,
		0x00,
	};

	assert_int_equal(scion_udp_deserialize(buf, 8, &udp), 0);

	assert_uint_equal(udp.src_port, 31337);
	assert_uint_equal(udp.dst_port, 31000);
	assert_uint_equal(udp.data_length, 0);
	assert_null(udp.data);
}

int run_udp_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_serialize_udp),
		cmocka_unit_test(test_deserialize_udp),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
