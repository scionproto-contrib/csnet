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
		= { .type = SCION_SCMP_TYPE_ECHO_REQUEST, .id = 1, .seqno = 2, .data_length = 4, .data = data };

	uint8_t buf[11];
	assert_int_equal(scion_scmp_echo_serialize(&echo, buf, sizeof(buf)), SCION_ERR_BUF_TOO_SMALL);
}

static void test_deserialize_scmp_echo(void **)
{
	const uint8_t buf[] = { 0x80, 0x00, 0x00, 0x00, 0xff, 0xfe, 0x00, 0x01, 0x18, 0x09, 0x58 };

	struct scion_scmp_echo echo;
	assert_int_equal(scion_scmp_echo_deserialize(buf, sizeof(buf), &echo), 0);

	assert_int_equal(echo.type, SCION_SCMP_TYPE_ECHO_REQUEST);
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

	assert_int_equal(echo.type, SCION_SCMP_TYPE_ECHO_REPLY);
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

static uint8_t quoted_packet[] = { 0xaa, 0xbb, 0xcc };

#define BYTES(...) .bytes = (const uint8_t[]){ __VA_ARGS__ }, .length = sizeof((const uint8_t[]){ __VA_ARGS__ })

// Every SCMP error message type with its serialized form.
static const struct {
	struct scion_scmp_error error;
	const uint8_t *bytes;
	size_t length;
} error_cases[] = {
	// Destination unreachable, port unreachable, with a quoted packet
	{ .error = { .type = SCION_SCMP_TYPE_DESTINATION_UNREACHABLE,
		  .code = SCION_SCMP_CODE_DESTINATION_UNREACHABLE_PORT_UNREACHABLE,
		  .packet = quoted_packet,
		  .packet_length = sizeof(quoted_packet) },
		BYTES(0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb, 0xcc) },
	// Packet too big, MTU 1400
	{ .error = { .type = SCION_SCMP_TYPE_PACKET_TOO_BIG, .info.packet_too_big.mtu = 1400 },
		BYTES(0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x78) },
	// Parameter problem, invalid hop field MAC, pointing to byte 258
	{ .error = { .type = SCION_SCMP_TYPE_PARAMETER_PROBLEM,
		  .code = SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_HOP_FIELD_MAC,
		  .info.parameter_problem.pointer = 258 },
		BYTES(0x04, 0x33, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02) },
	// External interface down, interface 42 of 1-ff00:0:111
	{ .error = { .type = SCION_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN,
		  .info.external_interface_down = { .ia = 0x1ff0000000111, .interface = 42 } },
		BYTES(0x05, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x2a) },
	// Internal connectivity down, interface 1 to interface 2 of 1-ff00:0:111
	{ .error = { .type = SCION_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN,
		  .info.internal_connectivity_down = { .ia = 0x1ff0000000111, .ingress_interface = 1, .egress_interface = 2 } },
		BYTES(0x06, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x01, 0x11, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02) },
};

static void assert_scmp_error_equal(const struct scion_scmp_error *actual, const struct scion_scmp_error *expected)
{
	assert_int_equal(actual->type, expected->type);
	assert_uint_equal(actual->code, expected->code);

	switch (expected->type) {
	case SCION_SCMP_TYPE_DESTINATION_UNREACHABLE:
		break;
	case SCION_SCMP_TYPE_PACKET_TOO_BIG:
		assert_uint_equal(actual->info.packet_too_big.mtu, expected->info.packet_too_big.mtu);
		break;
	case SCION_SCMP_TYPE_PARAMETER_PROBLEM:
		assert_uint_equal(actual->info.parameter_problem.pointer, expected->info.parameter_problem.pointer);
		break;
	case SCION_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN:
		assert_true(actual->info.external_interface_down.ia == expected->info.external_interface_down.ia);
		assert_true(actual->info.external_interface_down.interface == expected->info.external_interface_down.interface);
		break;
	case SCION_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN:
		assert_true(actual->info.internal_connectivity_down.ia == expected->info.internal_connectivity_down.ia);
		assert_true(actual->info.internal_connectivity_down.ingress_interface
					== expected->info.internal_connectivity_down.ingress_interface);
		assert_true(actual->info.internal_connectivity_down.egress_interface
					== expected->info.internal_connectivity_down.egress_interface);
		break;
	}

	assert_uint_equal(actual->packet_length, expected->packet_length);
	if (expected->packet_length > 0) {
		assert_memory_equal(actual->packet, expected->packet, expected->packet_length);
	} else {
		assert_null(actual->packet);
	}
}

static void test_serialize_scmp_error(void **)
{
	for (size_t i = 0; i < sizeof(error_cases) / sizeof(error_cases[0]); i++) {
		assert_uint_equal(scion_scmp_error_len(&error_cases[i].error), error_cases[i].length);

		uint8_t buf[64];
		assert_int_equal(scion_scmp_error_serialize(&error_cases[i].error, buf, sizeof(buf)), 0);
		assert_memory_equal(buf, error_cases[i].bytes, error_cases[i].length);
	}
}

static void test_deserialize_scmp_error(void **)
{
	for (size_t i = 0; i < sizeof(error_cases) / sizeof(error_cases[0]); i++) {
		struct scion_scmp_error error;
		assert_int_equal(scion_scmp_error_deserialize(error_cases[i].bytes, error_cases[i].length, &error), 0);
		assert_scmp_error_equal(&error, &error_cases[i].error);
		scion_scmp_error_free_members(&error);
	}
}

static void test_serialize_scmp_error_buffer_too_small(void **)
{
	for (size_t i = 0; i < sizeof(error_cases) / sizeof(error_cases[0]); i++) {
		uint8_t buf[64];
		assert_int_equal(scion_scmp_error_serialize(&error_cases[i].error, buf, error_cases[i].length - 1),
			SCION_ERR_BUF_TOO_SMALL);
	}
}

static void test_scmp_error_unknown_type(void **)
{
	struct scion_scmp_error error = { .type = (enum scion_scmp_type)3 };

	uint8_t buf[64];
	assert_uint_equal(scion_scmp_error_len(&error), 0);
	assert_int_equal(scion_scmp_error_serialize(&error, buf, sizeof(buf)), SCION_ERR_PACKET_FIELD_INVALID);

	// An informational message is not an error either.
	error.type = SCION_SCMP_TYPE_ECHO_REQUEST;
	assert_uint_equal(scion_scmp_error_len(&error), 0);
	assert_int_equal(scion_scmp_error_serialize(&error, buf, sizeof(buf)), SCION_ERR_PACKET_FIELD_INVALID);

	// 3 is unassigned, 128 is an informational message and 100 is reserved for private experimentation.
	const uint8_t types[] = { 0, 3, 100, 128 };
	for (size_t i = 0; i < sizeof(types); i++) {
		const uint8_t msg[] = { types[i], 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		assert_int_equal(scion_scmp_error_deserialize(msg, sizeof(msg), &error), SCION_ERR_PACKET_FIELD_INVALID);
	}
}

static void test_deserialize_scmp_error_too_short(void **)
{
	struct scion_scmp_error error;

	// Shorter than the SCMP header.
	assert_int_equal(scion_scmp_error_deserialize(error_cases[0].bytes, 3, &error), SCION_ERR_BUF_TOO_SMALL);

	// The type specific information is cut off.
	for (size_t i = 1; i < sizeof(error_cases) / sizeof(error_cases[0]); i++) {
		assert_int_equal(scion_scmp_error_deserialize(error_cases[i].bytes, error_cases[i].length - 1, &error),
			SCION_ERR_BUF_TOO_SMALL);
	}
}

static void test_deserialize_scmp_error_does_not_validate_code(void **)
{
	// The code is not validated, so codes allocated in the future are still passed on.
	const uint8_t msg[] = { 0x01, 0x63, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

	struct scion_scmp_error error;
	assert_int_equal(scion_scmp_error_deserialize(msg, sizeof(msg), &error), 0);
	assert_uint_equal(error.code, 99);
	assert_null(error.packet);
	assert_uint_equal(error.packet_length, 0);
}

static void test_scmp_error_free_members(void **)
{
	struct scion_scmp_error error;
	assert_int_equal(scion_scmp_error_deserialize(error_cases[0].bytes, error_cases[0].length, &error), 0);
	assert_non_null(error.packet);

	scion_scmp_error_free_members(&error);
	assert_null(error.packet);
	assert_uint_equal(error.packet_length, 0);
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
		cmocka_unit_test(test_serialize_scmp_error),
		cmocka_unit_test(test_deserialize_scmp_error),
		cmocka_unit_test(test_serialize_scmp_error_buffer_too_small),
		cmocka_unit_test(test_scmp_error_unknown_type),
		cmocka_unit_test(test_deserialize_scmp_error_too_short),
		cmocka_unit_test(test_deserialize_scmp_error_does_not_validate_code),
		cmocka_unit_test(test_scmp_error_free_members),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
