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

#include "data_plane/scmp.h"
#include "test_scmp.h"

static void test_serialize_scmp_echo(void **)
{
	// clang-format off
	const uint8_t data[] = {
		0x18, 0x09, 0x58, 0x68, 0x86, 0x08, 0xb1, 0x10
	};
	// clang-format on

	struct scion_scmp_echo echo = { 0 };
	echo.type = 128;
	echo.id = 65534;
	echo.seqno = 1;
	echo.data = (uint8_t *)&data;
	echo.data_length = 8;

	uint16_t buf_len = 16;
	uint8_t buf[buf_len];

	assert_int_equal(scion_scmp_echo_serialize(&echo, buf, buf_len), 0);

	// clang-format off
	const uint8_t test_buf[] = {
		0x80, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x01,
		0x18, 0x09, 0x58, 0x68, 0x86, 0x08, 0xb1, 0x10
	};

	// Once checksum is implemented, use the following test buffer instead:
	// const uint8_t test_buf[] = {
	// 	0x80, 0x00, 0x94, 0xf1, 0xff, 0xfe, 0x00, 0x01,
	// 	0x18, 0x09, 0x58, 0x68, 0x86, 0x08, 0xb1, 0x10
	// };
	// clang-format on

	assert_memory_equal(buf, test_buf, sizeof(buf));
}

int run_scmp_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_serialize_scmp_echo),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
