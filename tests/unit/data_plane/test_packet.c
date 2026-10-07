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
#include <string.h>

#include "data_plane/packet.h"
#include "data_plane/udp.h"
#include "test_packet.h"

static void test_serialize_scion_packet(void **)
{
	struct scion_packet packet = { 0 };
	packet.version = 0;
	packet.traffic_class = 0;
	packet.flow_id = 1;
	packet.next_hdr = SCION_PROTO_UDP;
	packet.path_type = SCION_PATH_TYPE_SCION;
	packet.dst_ia = 0x1ff0000000121;
	packet.src_ia = 0x2ff0000000221;

	packet.dst_addr_type = SCION_ADDR_TYPE_T4IP;
	packet.raw_dst_addr_length = 4;
	packet.raw_dst_addr = (uint8_t *)malloc(4);
	struct sockaddr_in dst_sockaddr;
	dst_sockaddr.sin_addr.s_addr = inet_addr("127.0.0.102");
	memcpy(packet.raw_dst_addr, &(dst_sockaddr.sin_addr.s_addr), 4);

	packet.src_addr_type = SCION_ADDR_TYPE_T4IP;
	packet.raw_src_addr_length = 4;
	packet.raw_src_addr = (uint8_t *)malloc(4);
	struct sockaddr_in src_sockaddr;
	src_sockaddr.sin_addr.s_addr = inet_addr("127.0.0.189");
	memcpy(packet.raw_src_addr, &(src_sockaddr.sin_addr.s_addr), 4);

	// clang-format off
    const uint8_t raw_path_buf[] = {
		0x00, 0x00, 0x20, 0x82, 0x00, 0x00, 0x36, 0x72,
        0x67, 0x37, 0x5e, 0xfc, 0x00, 0x00, 0x6d, 0x1d,
        0x67, 0x37, 0x5e, 0xb3, 0x01, 0x00, 0xf9, 0x5f,
        0x67, 0x37, 0x5e, 0xae, 0x00, 0x3f, 0x00, 0x02,
        0x00, 0x00, 0x87, 0x2d, 0x92, 0x63, 0xd1, 0x97,
        0x00, 0x3f, 0x00, 0x00, 0x01, 0xf4, 0xae, 0xe2,
        0x32, 0xfe, 0xe4, 0xdf, 0x00, 0x3f, 0x01, 0xf6,
        0x00, 0x00, 0x31, 0x76, 0xc2, 0x99, 0x18, 0xf2,
        0x00, 0x3f, 0x00, 0x00, 0x00, 0x03, 0xe1, 0x00,
        0x16, 0xdf, 0xd5, 0x4b, 0x00, 0x3f, 0x00, 0x00,
        0x00, 0x04, 0x25, 0x66, 0x37, 0x02, 0x8d, 0xda,
        0x00, 0x3f, 0x00, 0x03, 0x00, 0x00, 0x2c, 0xad,
        0xf3, 0x51, 0xb8, 0xbd,
	};
	// clang-format on

	struct scion_path_raw raw_path = { 0 };
	raw_path.length = sizeof(raw_path_buf);
	raw_path.raw = (uint8_t *)&raw_path_buf;

	struct scion_path path = { 0 };
	path.dst = packet.dst_ia;
	path.src = packet.src_ia;
	path.path_type = SCION_PATH_TYPE_SCION;
	path.raw_path = &raw_path;

	packet.path = &path;

	const uint8_t data[] = { 0x61, 0x62, 0x63 };
	struct scion_udp udp_packet = { 0 };
	udp_packet.data_length = sizeof(data);
	udp_packet.data = (uint8_t *)&data;
	udp_packet.dst_port = 31000;
	udp_packet.src_port = 31000;

	packet.payload_len = scion_udp_len(&udp_packet);
	packet.payload = (uint8_t *)malloc(packet.payload_len);

	int ret = (int)scion_udp_serialize(&udp_packet, packet.payload, &packet.payload_len);
	assert_int_equal(ret, 0);

	size_t packet_length = scion_packet_len(&packet);
	uint8_t *packet_buf = malloc(packet_length);

	ret = scion_packet_serialize(&packet, packet_buf, &packet_length);
	assert_int_equal(ret, 0);

	// clang-format off
	const uint8_t test_buf[] = {
		0x00, 0x00, 0x00, 0x01, 0x11, 0x22, 0x00, 0x0b,
        0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00,
        0x00, 0x00, 0x01, 0x21, 0x00, 0x02, 0xff, 0x00,
        0x00, 0x00, 0x02, 0x21, 0x7f, 0x00, 0x00, 0x66,
        0x7f, 0x00, 0x00, 0xbd, 0x00, 0x00, 0x20, 0x82,
        0x00, 0x00, 0x36, 0x72, 0x67, 0x37, 0x5e, 0xfc,
        0x00, 0x00, 0x6d, 0x1d, 0x67, 0x37, 0x5e, 0xb3,
        0x01, 0x00, 0xf9, 0x5f, 0x67, 0x37, 0x5e, 0xae,
        0x00, 0x3f, 0x00, 0x02, 0x00, 0x00, 0x87, 0x2d,
        0x92, 0x63, 0xd1, 0x97, 0x00, 0x3f, 0x00, 0x00,
        0x01, 0xf4, 0xae, 0xe2, 0x32, 0xfe, 0xe4, 0xdf,
        0x00, 0x3f, 0x01, 0xf6, 0x00, 0x00, 0x31, 0x76,
        0xc2, 0x99, 0x18, 0xf2, 0x00, 0x3f, 0x00, 0x00,
        0x00, 0x03, 0xe1, 0x00, 0x16, 0xdf, 0xd5, 0x4b,
        0x00, 0x3f, 0x00, 0x00, 0x00, 0x04, 0x25, 0x66,
        0x37, 0x02, 0x8d, 0xda, 0x00, 0x3f, 0x00, 0x03,
        0x00, 0x00, 0x2c, 0xad, 0xf3, 0x51, 0xb8, 0xbd,
        // TODO - update the last 2 checksum bytes when fixed in scion_udp_serialize
        0x79, 0x18, 0x79, 0x18, 0x00, 0x0b, 0x00, 0x00,
        0x61, 0x62, 0x63,
	};
	// clang-format on

	assert_memory_equal(packet_buf, test_buf, packet_length);

	free(packet.raw_dst_addr);
	free(packet.raw_src_addr);
	free(packet.payload);
	free(packet_buf);
}

static void test_deserialize_scion_packet(void **)
{
	// Path from AS 221 to AS 121 in the test topology

	// clang-format off
	const uint8_t buf[] = {
		0x00, 0x00, 0x00, 0x01, 0x11, 0x22, 0x00, 0x0b,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0xff, 0x00,
		0x00, 0x00, 0x01, 0x21, 0x00, 0x02, 0xff, 0x00,
		0x00, 0x00, 0x02, 0x21, 0x7f, 0x00, 0x00, 0x66,
		0x7f, 0x00, 0x00, 0xbd, 0x85, 0x00, 0x20, 0x82,
		0x00, 0x00, 0x98, 0x90, 0x67, 0x37, 0x5e, 0xfc,
		0x00, 0x00, 0x8c, 0x1d, 0x67, 0x37, 0x5e, 0xb3,
		0x01, 0x00, 0xdc, 0x39, 0x67, 0x37, 0x5e, 0xae,
		0x00, 0x3f, 0x00, 0x02, 0x00, 0x00, 0x87, 0x2d,
		0x92, 0x63, 0xd1, 0x97, 0x00, 0x3f, 0x00, 0x00,
		0x01, 0xf4, 0xae, 0xe2, 0x32, 0xfe, 0xe4, 0xdf,
		0x00, 0x3f, 0x01, 0xf6, 0x00, 0x00, 0x31, 0x76,
		0xc2, 0x99, 0x18, 0xf2, 0x00, 0x3f, 0x00, 0x00,
		0x00, 0x03, 0xe1, 0x00, 0x16, 0xdf, 0xd5, 0x4b,
		0x00, 0x3f, 0x00, 0x00, 0x00, 0x04, 0x25, 0x66,
		0x37, 0x02, 0x8d, 0xda, 0x00, 0x3f, 0x00, 0x03,
		0x00, 0x00, 0x2c, 0xad, 0xf3, 0x51, 0xb8, 0xbd,
		0x79, 0x18, 0x79, 0x18, 0x00, 0x0b, 0x48, 0xda,
		0x61, 0x62, 0x63,
	};

	const uint8_t dst_host[] = { 0x7f, 0x00, 0x00, 0x66 };
	const uint8_t src_host[] = { 0x7f, 0x00, 0x00, 0xbd };

	const uint8_t path_buf[] = {
		0x85, 0x00, 0x20, 0x82, 0x00, 0x00, 0x98, 0x90,
		0x67, 0x37, 0x5e, 0xfc, 0x00, 0x00, 0x8c, 0x1d,
		0x67, 0x37, 0x5e, 0xb3, 0x01, 0x00, 0xdc, 0x39,
		0x67, 0x37, 0x5e, 0xae, 0x00, 0x3f, 0x00, 0x02,
		0x00, 0x00, 0x87, 0x2d, 0x92, 0x63, 0xd1, 0x97,
		0x00, 0x3f, 0x00, 0x00, 0x01, 0xf4, 0xae, 0xe2,
		0x32, 0xfe, 0xe4, 0xdf, 0x00, 0x3f, 0x01, 0xf6,
		0x00, 0x00, 0x31, 0x76, 0xc2, 0x99, 0x18, 0xf2,
		0x00, 0x3f, 0x00, 0x00, 0x00, 0x03, 0xe1, 0x00,
		0x16, 0xdf, 0xd5, 0x4b, 0x00, 0x3f, 0x00, 0x00,
		0x00, 0x04, 0x25, 0x66, 0x37, 0x02, 0x8d, 0xda,
		0x00, 0x3f, 0x00, 0x03, 0x00, 0x00, 0x2c, 0xad,
		0xf3, 0x51, 0xb8, 0xbd,
	};

	uint8_t udp_buf[] = {
		0x79, 0x18, 0x79, 0x18, 0x00, 0x0b, 0x48, 0xda,
	};

	// clang-format on

	struct scion_packet packet = { 0 };
	assert_int_equal(scion_packet_deserialize(buf, sizeof(buf), &packet), 0);

	assert_uint_equal(packet.version, 0);
	assert_uint_equal(packet.traffic_class, 0);
	assert_uint_equal(packet.flow_id, 1);
	assert_uint_equal(packet.next_hdr, SCION_PROTO_UDP);
	assert_uint_equal(packet.payload_len, 11);
	assert_uint_equal(packet.path_type, SCION_PATH_TYPE_SCION);
	assert_uint_equal(packet.dst_addr_type, SCION_ADDR_TYPE_T4IP);
	assert_uint_equal(packet.src_addr_type, SCION_ADDR_TYPE_T4IP);
	assert_uint_equal(packet.dst_ia, 0x1ff0000000121);
	assert_uint_equal(packet.src_ia, 0x2ff0000000221);
	assert_uint_equal(packet.raw_dst_addr_length, 4);
	assert_memory_equal(dst_host, packet.raw_dst_addr, packet.raw_dst_addr_length);
	assert_uint_equal(packet.raw_src_addr_length, 4);
	assert_memory_equal(src_host, packet.raw_src_addr, packet.raw_src_addr_length);
	assert_uint_equal(packet.path->raw_path->length, sizeof(path_buf));
	assert_memory_equal(path_buf, packet.path->raw_path->raw, sizeof(path_buf));
	assert_memory_equal(udp_buf, packet.payload, sizeof(udp_buf));

	free(packet.raw_dst_addr);
	free(packet.raw_src_addr);
	free(packet.path->raw_path->raw);
	free(packet.path->raw_path);
	free(packet.path);
	free(packet.payload);
}

// A SCION packet with an empty path, IPv4 addresses and a 3 byte payload "abc".
// clang-format off
static const uint8_t empty_path_packet[] = {
	0x00, 0x00, 0x00, 0x01, 0x11, 0x09, 0x00, 0x03,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x01, 0x21,
	0x00, 0x02, 0xff, 0x00, 0x00, 0x00, 0x02, 0x21,
	0x7f, 0x00, 0x00, 0x66, 0x7f, 0x00, 0x00, 0xbd,
	0x61, 0x62, 0x63,
};
// clang-format on

#define EMPTY_PATH_HDR_LEN 36

static void init_empty_path_packet(struct scion_packet *packet)
{
	*packet = (struct scion_packet){ 0 };
	packet->flow_id = 1;
	packet->next_hdr = SCION_PROTO_UDP;
	packet->path_type = SCION_PATH_TYPE_EMPTY;
	packet->dst_ia = 0x1ff0000000121;
	packet->src_ia = 0x2ff0000000221;

	packet->dst_addr_type = SCION_ADDR_TYPE_T4IP;
	packet->raw_dst_addr_length = 4;
	packet->raw_dst_addr = malloc(4);
	memcpy(packet->raw_dst_addr, &empty_path_packet[28], 4);

	packet->src_addr_type = SCION_ADDR_TYPE_T4IP;
	packet->raw_src_addr_length = 4;
	packet->raw_src_addr = malloc(4);
	memcpy(packet->raw_src_addr, &empty_path_packet[32], 4);

	packet->payload_len = 3;
	packet->payload = malloc(3);
	memcpy(packet->payload, "abc", 3);
}

static void test_packet_addr_type_len(void **)
{
	assert_int_equal(scion_packet_addr_type_len(0), 4);
	assert_int_equal(scion_packet_addr_type_len(1), 8);
	assert_int_equal(scion_packet_addr_type_len(2), 12);
	assert_int_equal(scion_packet_addr_type_len(3), 16);
}

static void test_serialize_scion_packet_empty_path(void **)
{
	struct scion_packet packet;
	init_empty_path_packet(&packet);

	uint8_t buf[sizeof(empty_path_packet)];
	size_t buf_len = sizeof(buf);
	int ret = scion_packet_serialize(&packet, buf, &buf_len);
	scion_packet_free_members(&packet);

	assert_int_equal(ret, 0);
	assert_uint_equal(buf_len, sizeof(empty_path_packet));
	assert_memory_equal(buf, empty_path_packet, sizeof(empty_path_packet));
}

static void test_serialize_scion_packet_buffer_too_small(void **)
{
	struct scion_packet packet;
	init_empty_path_packet(&packet);

	uint8_t buf[sizeof(empty_path_packet) - 1];
	size_t buf_len = sizeof(buf);
	int ret = scion_packet_serialize(&packet, buf, &buf_len);
	scion_packet_free_members(&packet);

	assert_int_equal(ret, SCION_ERR_BUF_TOO_SMALL);
}

static void test_serialize_scion_packet_header_too_large(void **)
{
	struct scion_packet packet;
	init_empty_path_packet(&packet);

	// 12 + 24 + 1000 bytes exceeds the largest header the hdr_len field can express.
	struct scion_path_raw raw_path = { .length = 1000, .raw = NULL };
	struct scion_path path = { .path_type = SCION_PATH_TYPE_SCION, .raw_path = &raw_path };
	packet.path_type = SCION_PATH_TYPE_SCION;
	packet.path = &path;

	uint8_t buf[sizeof(empty_path_packet)];
	size_t buf_len = sizeof(buf);
	int ret = scion_packet_serialize(&packet, buf, &buf_len);

	packet.path = NULL;
	scion_packet_free_members(&packet);

	assert_int_equal(ret, SCION_ERR_MAX_HDR_LEN_EXCEEDED);
}

static void test_deserialize_scion_packet_empty_path(void **)
{
	struct scion_packet packet = { 0 };
	int ret = scion_packet_deserialize(empty_path_packet, sizeof(empty_path_packet), &packet);

	if (ret == 0) {
		assert_uint_equal(packet.flow_id, 1);
		assert_uint_equal(packet.next_hdr, SCION_PROTO_UDP);
		assert_uint_equal(packet.path_type, SCION_PATH_TYPE_EMPTY);
		assert_uint_equal(packet.dst_ia, 0x1ff0000000121);
		assert_uint_equal(packet.src_ia, 0x2ff0000000221);
		assert_null(packet.path->raw_path);
		assert_uint_equal(packet.payload_len, 3);
		assert_memory_equal(packet.payload, "abc", 3);
	}

	scion_packet_free_members(&packet);
	assert_int_equal(ret, 0);
}

static void assert_deserialize_fails(const uint8_t *buf, size_t buf_len, int expected_error)
{
	struct scion_packet packet = { 0 };
	int ret = scion_packet_deserialize(buf, buf_len, &packet);
	scion_packet_free_members(&packet);

	assert_int_equal(ret, expected_error);
}

static void test_deserialize_scion_packet_shorter_than_common_header(void **)
{
	assert_deserialize_fails(empty_path_packet, SCION_CMN_HDR_LEN - 1, SCION_ERR_NOT_ENOUGH_DATA);
}

static void test_deserialize_scion_packet_truncated_address_header(void **)
{
	assert_deserialize_fails(empty_path_packet, SCION_CMN_HDR_LEN + 15, SCION_ERR_BUF_TOO_SMALL);
}

static void test_deserialize_scion_packet_truncated_payload(void **)
{
	assert_deserialize_fails(empty_path_packet, sizeof(empty_path_packet) - 1, SCION_ERR_NOT_ENOUGH_DATA);
}

static void test_deserialize_scion_packet_hdr_len_shorter_than_headers(void **)
{
	uint8_t buf[sizeof(empty_path_packet)];
	memcpy(buf, empty_path_packet, sizeof(buf));
	buf[5] = (EMPTY_PATH_HDR_LEN - 4) / 4;

	assert_deserialize_fails(buf, sizeof(buf), SCION_ERR_PACKET_FIELD_INVALID);
}

// An empty path has no path header, so a hdr_len announcing extra bytes is malformed. It must not make the payload be
// read from the wrong offset.
static void test_deserialize_scion_packet_empty_path_with_path_header(void **)
{
	uint8_t buf[sizeof(empty_path_packet) + 4];
	memcpy(buf, empty_path_packet, EMPTY_PATH_HDR_LEN);
	buf[5] = (EMPTY_PATH_HDR_LEN + 4) / 4;
	memcpy(&buf[EMPTY_PATH_HDR_LEN], (uint8_t[]){ 0xde, 0xad, 0xbe, 0xef }, 4);
	memcpy(&buf[EMPTY_PATH_HDR_LEN + 4], "abc", 3);

	assert_deserialize_fails(buf, sizeof(buf), SCION_ERR_PACKET_FIELD_INVALID);
}

int run_packet_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_serialize_scion_packet),
		cmocka_unit_test(test_deserialize_scion_packet),
		cmocka_unit_test(test_packet_addr_type_len),
		cmocka_unit_test(test_serialize_scion_packet_empty_path),
		cmocka_unit_test(test_serialize_scion_packet_buffer_too_small),
		cmocka_unit_test(test_serialize_scion_packet_header_too_large),
		cmocka_unit_test(test_deserialize_scion_packet_empty_path),
		cmocka_unit_test(test_deserialize_scion_packet_shorter_than_common_header),
		cmocka_unit_test(test_deserialize_scion_packet_truncated_address_header),
		cmocka_unit_test(test_deserialize_scion_packet_truncated_payload),
		cmocka_unit_test(test_deserialize_scion_packet_hdr_len_shorter_than_headers),
		cmocka_unit_test(test_deserialize_scion_packet_empty_path_with_path_header),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
