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

static void test_serialize_scmp_echo_buffer_too_small(void **)
{
	uint8_t data[] = { 1, 2, 3, 4 };
	struct scion_scmp_echo echo
		= { .type = SCION_ECHO_TYPE_REQUEST, .id = 1, .seqno = 2, .data_length = 4, .data = data };

	uint8_t buf[11];
	assert_int_equal(scion_scmp_echo_serialize(&echo, buf, sizeof(buf)), SCION_ERR_BUF_TOO_SMALL);
}

static void test_deserialize_scmp_echo(void **)
{
	const uint8_t buf[] = { 0x80, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x01, 0x18, 0x09, 0x58 };

	struct scion_scmp_echo echo;
	assert_int_equal(scion_scmp_echo_deserialize(buf, sizeof(buf), &echo), 0);

	assert_int_equal(echo.type, SCION_ECHO_TYPE_REQUEST);
	assert_uint_equal(echo.id, 65534);
	assert_uint_equal(echo.seqno, 1);
	assert_uint_equal(echo.data_length, 3);
	assert_memory_equal(echo.data, &buf[8], 3);

	scion_scmp_echo_free_members(&echo);
}

static void test_deserialize_scmp_echo_reply_without_data(void **)
{
	const uint8_t buf[] = { 0x81, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x09 };

	struct scion_scmp_echo echo;
	assert_int_equal(scion_scmp_echo_deserialize(buf, sizeof(buf), &echo), 0);

	assert_int_equal(echo.type, SCION_ECHO_TYPE_REPLY);
	assert_uint_equal(echo.id, 7);
	assert_uint_equal(echo.seqno, 9);
	assert_uint_equal(echo.data_length, 0);
	assert_null(echo.data);
}

static void test_deserialize_scmp_echo_buffer_too_small(void **)
{
	const uint8_t buf[] = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00 };

	struct scion_scmp_echo echo;
	assert_int_equal(scion_scmp_echo_deserialize(buf, sizeof(buf), &echo), SCION_ERR_BUF_TOO_SMALL);
}

static void test_deserialize_scmp_echo_invalid_type(void **)
{
	// Type 1 is "destination unreachable", not an echo message.
	const uint8_t buf[] = { 0x01, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00, 0x09 };

	struct scion_scmp_echo echo;
	assert_int_equal(scion_scmp_echo_deserialize(buf, sizeof(buf), &echo), SCION_ERR_PACKET_FIELD_INVALID);
}

static void test_deserialize_scmp_echo_invalid_code(void **)
{
	const uint8_t buf[] = { 0x80, 0x01, 0x00, 0x00, 0x00, 0x07, 0x00, 0x09 };

	struct scion_scmp_echo echo;
	assert_int_equal(scion_scmp_echo_deserialize(buf, sizeof(buf), &echo), SCION_ERR_SCMP_CODE_INVALID);
}

static void test_scmp_type_code_and_error(void **)
{
	// Destination unreachable (type 1), code 2.
	const uint8_t error[] = { 0x01, 0x02 };
	assert_int_equal(scion_scmp_get_type(error, sizeof(error)), 1);
	assert_int_equal(scion_scmp_get_code(error, sizeof(error)), 2);
	assert_true(scion_scmp_is_error(error, sizeof(error)));

	// Echo request (type 128) is an informational message.
	const uint8_t echo[] = { 0x80, 0x00 };
	assert_int_equal(scion_scmp_get_type(echo, sizeof(echo)), 128);
	assert_int_equal(scion_scmp_get_code(echo, sizeof(echo)), 0);
	assert_false(scion_scmp_is_error(echo, sizeof(echo)));
}

static void test_scmp_type_and_code_of_short_buffer(void **)
{
	const uint8_t buf[] = { 0x80 };

	assert_int_equal(scion_scmp_get_type(buf, sizeof(buf)), 128);
	assert_int_equal(scion_scmp_get_code(buf, sizeof(buf)), 0);
	assert_int_equal(scion_scmp_get_type(buf, 0), 0);
}

int run_scmp_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_serialize_scmp_echo),
		cmocka_unit_test(test_serialize_scmp_echo_buffer_too_small),
		cmocka_unit_test(test_deserialize_scmp_echo),
		cmocka_unit_test(test_deserialize_scmp_echo_reply_without_data),
		cmocka_unit_test(test_deserialize_scmp_echo_buffer_too_small),
		cmocka_unit_test(test_deserialize_scmp_echo_invalid_type),
		cmocka_unit_test(test_deserialize_scmp_echo_invalid_code),
		cmocka_unit_test(test_scmp_type_code_and_error),
		cmocka_unit_test(test_scmp_type_and_code_of_short_buffer),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
