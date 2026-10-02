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

static void test_serialize_udp_with_data(void **)
{
	uint8_t data[] = { 'h', 'e', 'l', 'l', 'o' };
	struct scion_udp udp = { .src_port = 31337, .dst_port = 31000, .data_length = sizeof(data), .data = data };

	uint16_t buf_len = 13;
	uint8_t buf[13];
	assert_int_equal(scion_udp_serialize(&udp, buf, &buf_len), 0);

	const uint8_t expected[] = { 0x7a, 0x69, 0x79, 0x18, 0x00, 0x0d, 0x00, 0x00, 'h', 'e', 'l', 'l', 'o' };
	assert_memory_equal(buf, expected, sizeof(expected));
}

static void test_serialize_udp_buffer_too_small(void **)
{
	uint8_t data[] = { 'h', 'e', 'l', 'l', 'o' };
	struct scion_udp udp = { .src_port = 1, .dst_port = 2, .data_length = sizeof(data), .data = data };

	uint16_t buf_len = 12;
	uint8_t buf[12];
	assert_int_equal(scion_udp_serialize(&udp, buf, &buf_len), SCION_ERR_BUF_TOO_SMALL);
}

static void test_serialize_udp_message_too_large(void **)
{
	// The 8 byte header plus the payload no longer fits the 16 bit length field.
	struct scion_udp udp = { .src_port = 1, .dst_port = 2, .data_length = UINT16_MAX - 7, .data = NULL };

	uint16_t buf_len = 8;
	uint8_t buf[8];
	assert_int_equal(scion_udp_serialize(&udp, buf, &buf_len), SCION_ERR_MSG_TOO_LARGE);
}

static void test_deserialize_udp_with_data(void **)
{
	const uint8_t buf[] = { 0x7a, 0x69, 0x79, 0x18, 0x00, 0x0d, 0x00, 0x00, 'h', 'e', 'l', 'l', 'o' };

	struct scion_udp udp;
	assert_int_equal(scion_udp_deserialize(buf, sizeof(buf), &udp), 0);

	assert_uint_equal(udp.src_port, 31337);
	assert_uint_equal(udp.dst_port, 31000);
	assert_uint_equal(udp.data_length, 5);
	assert_memory_equal(udp.data, "hello", 5);

	scion_udp_free_members(&udp);
}

static void test_deserialize_udp_ignores_trailing_bytes(void **)
{
	// The payload length comes from the UDP length field, not from the size of the buffer.
	const uint8_t buf[] = { 0x00, 0x01, 0x00, 0x02, 0x00, 0x0a, 0x00, 0x00, 'a', 'b', 'c', 'd' };

	struct scion_udp udp;
	assert_int_equal(scion_udp_deserialize(buf, sizeof(buf), &udp), 0);

	assert_uint_equal(udp.data_length, 2);
	assert_memory_equal(udp.data, "ab", 2);

	scion_udp_free_members(&udp);
}

static void test_deserialize_udp_incomplete_header(void **)
{
	const uint8_t buf[] = { 0x7a, 0x69, 0x79, 0x18, 0x00, 0x08, 0x00 };

	struct scion_udp udp;
	assert_int_equal(scion_udp_deserialize(buf, sizeof(buf), &udp), SCION_ERR_NOT_ENOUGH_DATA);
}

static void test_deserialize_udp_length_shorter_than_header(void **)
{
	const uint8_t buf[] = { 0x7a, 0x69, 0x79, 0x18, 0x00, 0x04, 0x00, 0x00 };

	struct scion_udp udp;
	assert_int_equal(scion_udp_deserialize(buf, sizeof(buf), &udp), SCION_ERR_PACKET_FIELD_INVALID);
}

static void test_deserialize_udp_truncated_payload(void **)
{
	// Declares a 13 byte datagram but only 10 bytes are available.
	const uint8_t buf[] = { 0x7a, 0x69, 0x79, 0x18, 0x00, 0x0d, 0x00, 0x00, 'h', 'e' };

	struct scion_udp udp;
	assert_int_equal(scion_udp_deserialize(buf, sizeof(buf), &udp), SCION_ERR_NOT_ENOUGH_DATA);
}

int run_udp_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_serialize_udp),
		cmocka_unit_test(test_serialize_udp_with_data),
		cmocka_unit_test(test_serialize_udp_buffer_too_small),
		cmocka_unit_test(test_serialize_udp_message_too_large),
		cmocka_unit_test(test_deserialize_udp),
		cmocka_unit_test(test_deserialize_udp_with_data),
		cmocka_unit_test(test_deserialize_udp_ignores_trailing_bytes),
		cmocka_unit_test(test_deserialize_udp_incomplete_header),
		cmocka_unit_test(test_deserialize_udp_length_shorter_than_header),
		cmocka_unit_test(test_deserialize_udp_truncated_payload),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
