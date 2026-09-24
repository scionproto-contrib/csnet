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
#include <string.h>

#include "common/as_entry.h"
#include "common/info_field.h"
#include "data_plane/packet.h"
#include "data_plane/socket.h"
#include "data_plane/udp.h"
#include "test_deserialization.h"

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

static void test_deserialize_meta_hdr(void **)
{
	struct scion_path_meta_hdr hdr;

	const uint8_t buf[] = {
		0x87,
		0x00,
		0x30,
		0xc4,
	};

	assert_int_equal(scion_path_meta_hdr_deserialize((uint8_t *)&buf, &hdr), 0);

	assert_uint_equal(hdr.curr_inf, 2);
	assert_uint_equal(hdr.curr_hf, 7);
	assert_uint_equal(hdr.seg_len[0], 3);
	assert_uint_equal(hdr.seg_len[1], 3);
	assert_uint_equal(hdr.seg_len[2], 4);
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

static void test_deserialize_hop_field(void **)
{
	struct scion_hop_field hop_field;

	const uint8_t buf[] = {
		0x00,
		0x3f,
		0x01,
		0x2d,
		0x00,
		0x00,
		0x60,
		0xe4,
		0xba,
		0xd9,
		0xf1,
		0xbe,
	};

	const uint8_t mac[] = {
		0x60,
		0xe4,
		0xba,
		0xd9,
		0xf1,
		0xbe,
	};

	assert_int_equal(scion_hop_field_deserialize((uint8_t *)&buf, &hop_field), 0);

	assert_false(hop_field.ingress_router_alert);
	assert_false(hop_field.egress_router_alert);
	assert_uint_equal(hop_field.exp_time, 63);
	assert_uint_equal(hop_field.cons_ingress, 301);
	assert_uint_equal(hop_field.cons_egress, 0);
	assert_memory_equal(hop_field.mac, mac, sizeof(mac));
}

static void test_deserialize_path(void **)
{
	// Path from AS 221 to AS 121 in the test topology

	// clang-format off
	const uint8_t buf[] = {
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
	// clang-format on

	struct scion_path_meta_hdr hdr;
	struct scion_list *info_fields = scion_list_create(SCION_LIST_SIMPLE_FREE);
	struct scion_list *hop_fields = scion_list_create(SCION_LIST_SIMPLE_FREE);

	assert_int_equal(scion_path_deserialize((uint8_t *)&buf, &hdr, info_fields, hop_fields), 0);

	assert_uint_equal(hdr.curr_inf, 2);
	assert_uint_equal(hdr.curr_hf, 5);
	assert_uint_equal(hdr.seg_len[0], 2);
	assert_uint_equal(hdr.seg_len[1], 2);
	assert_uint_equal(hdr.seg_len[2], 2);

	assert_uint_equal(info_fields->size, 3);
	assert_uint_equal(hop_fields->size, 6);

	// Info Fields
	struct scion_list_node *curr = info_fields->first;
	struct scion_info_field *curr_if = (struct scion_info_field *)curr->value;
	assert_non_null(curr_if);
	assert_false(curr_if->peer);
	assert_false(curr_if->cons_dir);
	assert_uint_equal(curr_if->seg_id, 0x9890);
	assert_uint_equal(curr_if->timestamp, 0x67375efc);

	curr = curr->next;
	curr_if = (struct scion_info_field *)curr->value;
	assert_non_null(curr_if);
	assert_false(curr_if->peer);
	assert_false(curr_if->cons_dir);
	assert_uint_equal(curr_if->seg_id, 0x8c1d);
	assert_uint_equal(curr_if->timestamp, 0x67375eb3);

	curr = curr->next;
	curr_if = (struct scion_info_field *)curr->value;
	assert_non_null(curr_if);
	assert_false(curr_if->peer);
	assert_true(curr_if->cons_dir);
	assert_uint_equal(curr_if->seg_id, 0xdc39);
	assert_uint_equal(curr_if->timestamp, 0x67375eae);

	// Hop Fields
	curr = hop_fields->first;
	struct scion_hop_field *curr_hf = (struct scion_hop_field *)curr->value;
	uint8_t mac_0[6] = { 0x87, 0x2d, 0x92, 0x63, 0xd1, 0x97 };
	assert_non_null(curr_hf);
	assert_false(curr_hf->ingress_router_alert);
	assert_false(curr_hf->egress_router_alert);
	assert_uint_equal(curr_hf->exp_time, 63);
	assert_uint_equal(curr_hf->cons_ingress, 2);
	assert_uint_equal(curr_hf->cons_egress, 0);
	assert_memory_equal(curr_hf->mac, mac_0, sizeof(mac_0));

	curr = curr->next;
	curr_hf = (struct scion_hop_field *)curr->value;
	uint8_t mac_1[6] = { 0xae, 0xe2, 0x32, 0xfe, 0xe4, 0xdf };
	assert_non_null(curr_hf);
	assert_false(curr_hf->ingress_router_alert);
	assert_false(curr_hf->egress_router_alert);
	assert_uint_equal(curr_hf->exp_time, 63);
	assert_uint_equal(curr_hf->cons_ingress, 0);
	assert_uint_equal(curr_hf->cons_egress, 500);
	assert_memory_equal(curr_hf->mac, mac_1, sizeof(mac_1));

	curr = curr->next;
	curr_hf = (struct scion_hop_field *)curr->value;
	uint8_t mac_2[6] = { 0x31, 0x76, 0xc2, 0x99, 0x18, 0xf2 };
	assert_non_null(curr_hf);
	assert_false(curr_hf->ingress_router_alert);
	assert_false(curr_hf->egress_router_alert);
	assert_uint_equal(curr_hf->exp_time, 63);
	assert_uint_equal(curr_hf->cons_ingress, 502);
	assert_uint_equal(curr_hf->cons_egress, 0);
	assert_memory_equal(curr_hf->mac, mac_2, sizeof(mac_2));

	curr = curr->next;
	curr_hf = (struct scion_hop_field *)curr->value;
	uint8_t mac_3[6] = { 0xe1, 0x00, 0x16, 0xdf, 0xd5, 0x4b };
	assert_non_null(curr_hf);
	assert_false(curr_hf->ingress_router_alert);
	assert_false(curr_hf->egress_router_alert);
	assert_uint_equal(curr_hf->exp_time, 63);
	assert_uint_equal(curr_hf->cons_ingress, 0);
	assert_uint_equal(curr_hf->cons_egress, 3);
	assert_memory_equal(curr_hf->mac, mac_3, sizeof(mac_3));

	curr = curr->next;
	curr_hf = (struct scion_hop_field *)curr->value;
	uint8_t mac_4[6] = { 0x25, 0x66, 0x37, 0x02, 0x8d, 0xda };
	assert_non_null(curr_hf);
	assert_false(curr_hf->ingress_router_alert);
	assert_false(curr_hf->egress_router_alert);
	assert_uint_equal(curr_hf->exp_time, 63);
	assert_uint_equal(curr_hf->cons_ingress, 0);
	assert_uint_equal(curr_hf->cons_egress, 4);
	assert_memory_equal(curr_hf->mac, mac_4, sizeof(mac_4));

	curr = curr->next;
	curr_hf = (struct scion_hop_field *)curr->value;
	uint8_t mac_5[6] = { 0x2c, 0xad, 0xf3, 0x51, 0xb8, 0xbd };
	assert_non_null(curr_hf);
	assert_false(curr_hf->ingress_router_alert);
	assert_false(curr_hf->egress_router_alert);
	assert_uint_equal(curr_hf->exp_time, 63);
	assert_uint_equal(curr_hf->cons_ingress, 3);
	assert_uint_equal(curr_hf->cons_egress, 0);
	assert_memory_equal(curr_hf->mac, mac_5, sizeof(mac_5));

	scion_list_free(info_fields);
	scion_list_free(hop_fields);
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

int run_deserialization_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_deserialize_udp),
		cmocka_unit_test(test_deserialize_meta_hdr),
		cmocka_unit_test(test_deserialize_info_field),
		cmocka_unit_test(test_deserialize_hop_field),
		cmocka_unit_test(test_deserialize_path),
		cmocka_unit_test(test_deserialize_scion_packet),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
