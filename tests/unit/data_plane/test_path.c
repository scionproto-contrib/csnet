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
#include "common/isd_as.h"
#include "data_plane/path.h"
#include "test_path.h"
#include "util/list.h"

static void test_init_raw_path(void **)
{
	struct scion_path_meta_hdr hdr;
	hdr.curr_inf = 0;
	hdr.curr_hf = 0;
	hdr.seg_len[0] = 2;
	hdr.seg_len[1] = 2;
	hdr.seg_len[2] = 2;

	struct scion_list *info_fields = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	struct scion_info_field info_field_0;
	info_field_0.peer = false;
	info_field_0.cons_dir = false;
	info_field_0.seg_id = 0x3672;
	info_field_0.timestamp = 0x67375efc;

	struct scion_info_field info_field_1;
	info_field_1.peer = false;
	info_field_1.cons_dir = false;
	info_field_1.seg_id = 0x6d1d;
	info_field_1.timestamp = 0x67375eb3;

	struct scion_info_field info_field_2;
	info_field_2.peer = false;
	info_field_2.cons_dir = true;
	info_field_2.seg_id = 0xf95f;
	info_field_2.timestamp = 0x67375eae;

	scion_list_append(info_fields, &info_field_0);
	scion_list_append(info_fields, &info_field_1);
	scion_list_append(info_fields, &info_field_2);

	struct scion_list *hop_fields = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	struct scion_hop_field hop_field_0;
	hop_field_0.ingress_router_alert = false;
	hop_field_0.egress_router_alert = false;
	hop_field_0.exp_time = 63;
	hop_field_0.cons_ingress = 2;
	hop_field_0.cons_egress = 0;
	hop_field_0.mac[0] = 0x87;
	hop_field_0.mac[1] = 0x2d;
	hop_field_0.mac[2] = 0x92;
	hop_field_0.mac[3] = 0x63;
	hop_field_0.mac[4] = 0xd1;
	hop_field_0.mac[5] = 0x97;

	struct scion_hop_field hop_field_1;
	hop_field_1.ingress_router_alert = false;
	hop_field_1.egress_router_alert = false;
	hop_field_1.exp_time = 63;
	hop_field_1.cons_ingress = 0;
	hop_field_1.cons_egress = 500;
	hop_field_1.mac[0] = 0xae;
	hop_field_1.mac[1] = 0xe2;
	hop_field_1.mac[2] = 0x32;
	hop_field_1.mac[3] = 0xfe;
	hop_field_1.mac[4] = 0xe4;
	hop_field_1.mac[5] = 0xdf;

	struct scion_hop_field hop_field_2;
	hop_field_2.ingress_router_alert = false;
	hop_field_2.egress_router_alert = false;
	hop_field_2.exp_time = 63;
	hop_field_2.cons_ingress = 502;
	hop_field_2.cons_egress = 0;
	hop_field_2.mac[0] = 0x31;
	hop_field_2.mac[1] = 0x76;
	hop_field_2.mac[2] = 0xc2;
	hop_field_2.mac[3] = 0x99;
	hop_field_2.mac[4] = 0x18;
	hop_field_2.mac[5] = 0xf2;

	struct scion_hop_field hop_field_3;
	hop_field_3.ingress_router_alert = false;
	hop_field_3.egress_router_alert = false;
	hop_field_3.exp_time = 63;
	hop_field_3.cons_ingress = 0;
	hop_field_3.cons_egress = 3;
	hop_field_3.mac[0] = 0xe1;
	hop_field_3.mac[1] = 0x00;
	hop_field_3.mac[2] = 0x16;
	hop_field_3.mac[3] = 0xdf;
	hop_field_3.mac[4] = 0xd5;
	hop_field_3.mac[5] = 0x4b;

	struct scion_hop_field hop_field_4;
	hop_field_4.ingress_router_alert = false;
	hop_field_4.egress_router_alert = false;
	hop_field_4.exp_time = 63;
	hop_field_4.cons_ingress = 0;
	hop_field_4.cons_egress = 4;
	hop_field_4.mac[0] = 0x25;
	hop_field_4.mac[1] = 0x66;
	hop_field_4.mac[2] = 0x37;
	hop_field_4.mac[3] = 0x02;
	hop_field_4.mac[4] = 0x8d;
	hop_field_4.mac[5] = 0xda;

	struct scion_hop_field hop_field_5;
	hop_field_5.ingress_router_alert = false;
	hop_field_5.egress_router_alert = false;
	hop_field_5.exp_time = 63;
	hop_field_5.cons_ingress = 3;
	hop_field_5.cons_egress = 0;
	hop_field_5.mac[0] = 0x2c;
	hop_field_5.mac[1] = 0xad;
	hop_field_5.mac[2] = 0xf3;
	hop_field_5.mac[3] = 0x51;
	hop_field_5.mac[4] = 0xb8;
	hop_field_5.mac[5] = 0xbd;

	scion_list_append(hop_fields, &hop_field_0);
	scion_list_append(hop_fields, &hop_field_1);
	scion_list_append(hop_fields, &hop_field_2);
	scion_list_append(hop_fields, &hop_field_3);
	scion_list_append(hop_fields, &hop_field_4);
	scion_list_append(hop_fields, &hop_field_5);

	struct scion_path_raw raw_path = { 0 };
	int ret = scion_path_raw_init(&raw_path, &hdr, info_fields, hop_fields);

	scion_list_free(info_fields);
	scion_list_free(hop_fields);

	assert_int_equal(ret, 0);

	// clang-format off
	const uint8_t test_buf[] = {
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

	assert_uint_equal(raw_path.length, sizeof(test_buf));
	assert_memory_equal(raw_path.raw, test_buf, raw_path.length);

	free(raw_path.raw);
}

static void test_reverse_path(void **)
{
	// clang-format off
    // Path from AS 222 to AS 133
    uint8_t raw_path_buf[] = {
		0x8a, 0x00, 0x31, 0x04, 0x00, 0x00, 0xbc, 0xa0,
        0x67, 0x3c, 0x94, 0x2c, 0x00, 0x00, 0x1d, 0x45,
        0x67, 0x3c, 0x94, 0x2a, 0x01, 0x00, 0xa8, 0x81,
        0x67, 0x3c, 0x94, 0x24, 0x00, 0x3f, 0x01, 0x2d,
        0x00, 0x00, 0x52, 0xec, 0x27, 0xb3, 0x93, 0x97,
        0x00, 0x3f, 0x00, 0x07, 0x00, 0x04, 0x1c, 0xe0,
        0xb5, 0xd5, 0x20, 0xe0, 0x00, 0x3f, 0x00, 0x00,
        0x01, 0xc3, 0xb4, 0xf1, 0xbd, 0xd5, 0xf7, 0xa7,
        0x00, 0x3f, 0x01, 0xc2, 0x00, 0x00, 0x27, 0xdb,
        0xf5, 0xaa, 0xc9, 0x74, 0x00, 0x3f, 0x01, 0xf6,
        0x01, 0xf7, 0x8b, 0xf1, 0x12, 0x69, 0xa4, 0xd1,
        0x00, 0x3f, 0x00, 0x01, 0x00, 0x03, 0xc9, 0x98,
        0x08, 0x95, 0xd8, 0x17, 0x00, 0x3f, 0x00, 0x00,
        0x00, 0x69, 0x4c, 0x02, 0x3b, 0xd3, 0x7b, 0xc3,
        0x00, 0x3f, 0x00, 0x00, 0x00, 0x6f, 0x3d, 0x29,
        0x57, 0xdd, 0xce, 0x40, 0x00, 0x3f, 0x01, 0xdf,
        0x01, 0xde, 0x90, 0x83, 0x9b, 0xd1, 0x33, 0x97,
        0x00, 0x3f, 0x00, 0x02, 0x00, 0x01, 0x02, 0x15,
        0xf3, 0x9f, 0x69, 0x22, 0x00, 0x3f, 0x00, 0x02,
        0x00, 0x00, 0x7b, 0x26, 0x93, 0x71, 0x4f, 0x5b,
	};

    // Path reversed by Go code, now from AS 133 to AS 222
    uint8_t test_buf[] = {
        0x00, 0x00, 0x41, 0x03, 0x00, 0x00, 0xa8, 0x81,
        0x67, 0x3c, 0x94, 0x24, 0x01, 0x00, 0x1d, 0x45,
        0x67, 0x3c, 0x94, 0x2a, 0x01, 0x00, 0xbc, 0xa0,
        0x67, 0x3c, 0x94, 0x2c, 0x00, 0x3f, 0x00, 0x02,
        0x00, 0x00, 0x7b, 0x26, 0x93, 0x71, 0x4f, 0x5b,
        0x00, 0x3f, 0x00, 0x02, 0x00, 0x01, 0x02, 0x15,
        0xf3, 0x9f, 0x69, 0x22, 0x00, 0x3f, 0x01, 0xdf,
        0x01, 0xde, 0x90, 0x83, 0x9b, 0xd1, 0x33, 0x97,
        0x00, 0x3f, 0x00, 0x00, 0x00, 0x6f, 0x3d, 0x29,
        0x57, 0xdd, 0xce, 0x40, 0x00, 0x3f, 0x00, 0x00,
        0x00, 0x69, 0x4c, 0x02, 0x3b, 0xd3, 0x7b, 0xc3,
        0x00, 0x3f, 0x00, 0x01, 0x00, 0x03, 0xc9, 0x98,
        0x08, 0x95, 0xd8, 0x17, 0x00, 0x3f, 0x01, 0xf6,
        0x01, 0xf7, 0x8b, 0xf1, 0x12, 0x69, 0xa4, 0xd1,
        0x00, 0x3f, 0x01, 0xc2, 0x00, 0x00, 0x27, 0xdb,
        0xf5, 0xaa, 0xc9, 0x74, 0x00, 0x3f, 0x00, 0x00,
        0x01, 0xc3, 0xb4, 0xf1, 0xbd, 0xd5, 0xf7, 0xa7,
        0x00, 0x3f, 0x00, 0x07, 0x00, 0x04, 0x1c, 0xe0,
        0xb5, 0xd5, 0x20, 0xe0, 0x00, 0x3f, 0x01, 0x2d,
        0x00, 0x00, 0x52, 0xec, 0x27, 0xb3, 0x93, 0x97,
    };
	// clang-format on

	struct scion_path_raw raw_path = { 0 };
	raw_path.length = sizeof(raw_path_buf);
	raw_path.raw = (uint8_t *)&raw_path_buf;

	int ret = scion_path_raw_reverse(&raw_path);
	assert_true(ret >= 0);

	assert_memory_equal(test_buf, raw_path_buf, sizeof(test_buf));
}

static void test_serialize_meta_hdr(void **)
{
	struct scion_path_meta_hdr hdr;
	hdr.curr_inf = 2;
	hdr.curr_hf = 7;
	hdr.seg_len[0] = 3;
	hdr.seg_len[1] = 3;
	hdr.seg_len[2] = 4;

	uint8_t buf[4];
	assert_int_equal(scion_path_meta_hdr_serialize(&hdr, buf), 0);

	const uint8_t test_buf[] = {
		0x87,
		0x00,
		0x30,
		0xc4,
	};

	assert_memory_equal(buf, test_buf, sizeof(buf));
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

static void test_serialize_path(void **)
{
	// Path from AS 221 to AS 121 in the test topology

	struct scion_path_meta_hdr hdr;
	hdr.curr_inf = 0;
	hdr.curr_hf = 0;
	hdr.seg_len[0] = 2;
	hdr.seg_len[1] = 2;
	hdr.seg_len[2] = 2;

	struct scion_list *info_fields = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	struct scion_info_field info_field_0;
	info_field_0.peer = false;
	info_field_0.cons_dir = false;
	info_field_0.seg_id = 0x3672;
	info_field_0.timestamp = 0x67375efc;

	struct scion_info_field info_field_1;
	info_field_1.peer = false;
	info_field_1.cons_dir = false;
	info_field_1.seg_id = 0x6d1d;
	info_field_1.timestamp = 0x67375eb3;

	struct scion_info_field info_field_2;
	info_field_2.peer = false;
	info_field_2.cons_dir = true;
	info_field_2.seg_id = 0xf95f;
	info_field_2.timestamp = 0x67375eae;

	scion_list_append(info_fields, &info_field_0);
	scion_list_append(info_fields, &info_field_1);
	scion_list_append(info_fields, &info_field_2);

	struct scion_list *hop_fields = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	struct scion_hop_field hop_field_0;
	hop_field_0.ingress_router_alert = false;
	hop_field_0.egress_router_alert = false;
	hop_field_0.exp_time = 63;
	hop_field_0.cons_ingress = 2;
	hop_field_0.cons_egress = 0;
	hop_field_0.mac[0] = 0x87;
	hop_field_0.mac[1] = 0x2d;
	hop_field_0.mac[2] = 0x92;
	hop_field_0.mac[3] = 0x63;
	hop_field_0.mac[4] = 0xd1;
	hop_field_0.mac[5] = 0x97;

	struct scion_hop_field hop_field_1;
	hop_field_1.ingress_router_alert = false;
	hop_field_1.egress_router_alert = false;
	hop_field_1.exp_time = 63;
	hop_field_1.cons_ingress = 0;
	hop_field_1.cons_egress = 500;
	hop_field_1.mac[0] = 0xae;
	hop_field_1.mac[1] = 0xe2;
	hop_field_1.mac[2] = 0x32;
	hop_field_1.mac[3] = 0xfe;
	hop_field_1.mac[4] = 0xe4;
	hop_field_1.mac[5] = 0xdf;

	struct scion_hop_field hop_field_2;
	hop_field_2.ingress_router_alert = false;
	hop_field_2.egress_router_alert = false;
	hop_field_2.exp_time = 63;
	hop_field_2.cons_ingress = 502;
	hop_field_2.cons_egress = 0;
	hop_field_2.mac[0] = 0x31;
	hop_field_2.mac[1] = 0x76;
	hop_field_2.mac[2] = 0xc2;
	hop_field_2.mac[3] = 0x99;
	hop_field_2.mac[4] = 0x18;
	hop_field_2.mac[5] = 0xf2;

	struct scion_hop_field hop_field_3;
	hop_field_3.ingress_router_alert = false;
	hop_field_3.egress_router_alert = false;
	hop_field_3.exp_time = 63;
	hop_field_3.cons_ingress = 0;
	hop_field_3.cons_egress = 3;
	hop_field_3.mac[0] = 0xe1;
	hop_field_3.mac[1] = 0x00;
	hop_field_3.mac[2] = 0x16;
	hop_field_3.mac[3] = 0xdf;
	hop_field_3.mac[4] = 0xd5;
	hop_field_3.mac[5] = 0x4b;

	struct scion_hop_field hop_field_4;
	hop_field_4.ingress_router_alert = false;
	hop_field_4.egress_router_alert = false;
	hop_field_4.exp_time = 63;
	hop_field_4.cons_ingress = 0;
	hop_field_4.cons_egress = 4;
	hop_field_4.mac[0] = 0x25;
	hop_field_4.mac[1] = 0x66;
	hop_field_4.mac[2] = 0x37;
	hop_field_4.mac[3] = 0x02;
	hop_field_4.mac[4] = 0x8d;
	hop_field_4.mac[5] = 0xda;

	struct scion_hop_field hop_field_5;
	hop_field_5.ingress_router_alert = false;
	hop_field_5.egress_router_alert = false;
	hop_field_5.exp_time = 63;
	hop_field_5.cons_ingress = 3;
	hop_field_5.cons_egress = 0;
	hop_field_5.mac[0] = 0x2c;
	hop_field_5.mac[1] = 0xad;
	hop_field_5.mac[2] = 0xf3;
	hop_field_5.mac[3] = 0x51;
	hop_field_5.mac[4] = 0xb8;
	hop_field_5.mac[5] = 0xbd;

	scion_list_append(hop_fields, &hop_field_0);
	scion_list_append(hop_fields, &hop_field_1);
	scion_list_append(hop_fields, &hop_field_2);
	scion_list_append(hop_fields, &hop_field_3);
	scion_list_append(hop_fields, &hop_field_4);
	scion_list_append(hop_fields, &hop_field_5);

	uint8_t buf[100];
	int ret = scion_path_serialize(&hdr, info_fields, hop_fields, buf);

	scion_list_free(info_fields);
	scion_list_free(hop_fields);

	assert_int_equal(ret, 0);

	// clang-format off
	const uint8_t test_buf[] = {
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

	assert_memory_equal(buf, test_buf, sizeof(buf));
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

	assert_int_equal(scion_path_deserialize((uint8_t *)&buf, sizeof(buf), &hdr, info_fields, hop_fields), 0);

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

// scion_path_reverse() parses the raw path using the segment lengths announced in its meta header. A raw path that is
// shorter than that header claims (e.g. one taken from a malformed packet) must be rejected instead of being read past
// its end.
static void assert_reverse_rejects_raw_path(struct scion_path_meta_hdr *hdr, uint16_t raw_length)
{
	struct scion_path_raw raw_path = { .length = raw_length, .raw = calloc(raw_length, sizeof(uint8_t)) };
	if (raw_length >= SCION_META_LEN) {
		assert_int_equal(scion_path_meta_hdr_serialize(hdr, raw_path.raw), 0);
	}

	struct scion_path path = { .path_type = SCION_PATH_TYPE_SCION, .raw_path = &raw_path };
	assert_int_equal(scion_path_reverse(&path), SCION_ERR_NOT_ENOUGH_DATA);

	free(raw_path.raw);
}

static void test_reverse_path_shorter_than_meta_hdr(void **)
{
	struct scion_path_meta_hdr hdr = { 0 };
	assert_reverse_rejects_raw_path(&hdr, SCION_META_LEN - 1);
}

static void test_reverse_path_missing_info_fields(void **)
{
	// One segment with two hop fields, but only the meta header is present.
	struct scion_path_meta_hdr hdr = { .seg_len = { 2, 0, 0 } };
	assert_reverse_rejects_raw_path(&hdr, SCION_META_LEN);
}

static void test_reverse_path_missing_hop_fields(void **)
{
	// One segment with two hop fields, but the second hop field is cut short.
	struct scion_path_meta_hdr hdr = { .seg_len = { 2, 0, 0 } };
	assert_reverse_rejects_raw_path(&hdr, SCION_META_LEN + SCION_INFO_LEN + 2 * SCION_HOP_LEN - 1);
}

static void test_meta_hdr_init(void **)
{
	struct scion_path_meta_hdr hdr = { .curr_inf = 1, .curr_hf = 2, .seg_len = { 3, 4, 5 } };
	assert_int_equal(scion_path_meta_hdr_init(&hdr), 0);

	assert_uint_equal(hdr.curr_inf, 0);
	assert_uint_equal(hdr.curr_hf, 0);
	assert_uint_equal(hdr.seg_len[0], 0);
	assert_uint_equal(hdr.seg_len[1], 0);
	assert_uint_equal(hdr.seg_len[2], 0);
}

static void test_meta_hdr_round_trip_extremes(void **)
{
	struct scion_path_meta_hdr hdr = { .curr_inf = 3, .curr_hf = 63, .seg_len = { 63, 63, 63 } };

	uint8_t buf[SCION_META_LEN];
	assert_int_equal(scion_path_meta_hdr_serialize(&hdr, buf), 0);

	struct scion_path_meta_hdr parsed;
	assert_int_equal(scion_path_meta_hdr_deserialize(buf, &parsed), 0);
	assert_uint_equal(parsed.curr_inf, 3);
	assert_uint_equal(parsed.curr_hf, 63);
	assert_uint_equal(parsed.seg_len[0], 63);
	assert_uint_equal(parsed.seg_len[1], 63);
	assert_uint_equal(parsed.seg_len[2], 63);
}

// A segment can only be empty if no segment follows it.
static void test_deserialize_path_inconsistent_segment_lengths(void **)
{
	struct scion_path_meta_hdr hdr = { .seg_len = { 1, 0, 2 } };

	uint8_t buf[SCION_META_LEN];
	assert_int_equal(scion_path_meta_hdr_serialize(&hdr, buf), 0);

	struct scion_list *info_fields = scion_list_create(SCION_LIST_SIMPLE_FREE);
	struct scion_list *hop_fields = scion_list_create(SCION_LIST_SIMPLE_FREE);
	int ret = scion_path_deserialize(buf, sizeof(buf), &hdr, info_fields, hop_fields);
	scion_list_free(info_fields);
	scion_list_free(hop_fields);

	assert_int_equal(ret, SCION_ERR_META_HDR_INVALID);
}

static void test_path_get_numhops(void **)
{
	struct scion_path empty = { .path_type = SCION_PATH_TYPE_EMPTY };
	assert_uint_equal(scion_path_get_numhops(&empty), 0);

	struct scion_path_metadata metadata = { .interfaces_len = 6 };
	struct scion_path path = { .path_type = SCION_PATH_TYPE_SCION, .metadata = &metadata };
	assert_uint_equal(scion_path_get_numhops(&path), 4);
}

static void test_reverse_empty_path(void **)
{
	struct scion_path path = { .src = 1, .dst = 2, .path_type = SCION_PATH_TYPE_EMPTY };

	assert_int_equal(scion_path_reverse(&path), 0);

	assert_uint_equal(path.src, 2);
	assert_uint_equal(path.dst, 1);
}

static void test_reverse_unknown_path_type(void **)
{
	struct scion_path path = { .path_type = 5 };

	assert_int_equal(scion_path_reverse(&path), SCION_ERR_PATH_TYPE_INVALID);
}

int run_path_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_init_raw_path),
		cmocka_unit_test(test_reverse_path),
		cmocka_unit_test(test_reverse_path_shorter_than_meta_hdr),
		cmocka_unit_test(test_reverse_path_missing_info_fields),
		cmocka_unit_test(test_reverse_path_missing_hop_fields),
		cmocka_unit_test(test_meta_hdr_init),
		cmocka_unit_test(test_meta_hdr_round_trip_extremes),
		cmocka_unit_test(test_deserialize_path_inconsistent_segment_lengths),
		cmocka_unit_test(test_path_get_numhops),
		cmocka_unit_test(test_reverse_empty_path),
		cmocka_unit_test(test_reverse_unknown_path_type),
		cmocka_unit_test(test_serialize_meta_hdr),
		cmocka_unit_test(test_deserialize_meta_hdr),
		cmocka_unit_test(test_serialize_path),
		cmocka_unit_test(test_deserialize_path),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
