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

#include <arpa/inet.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "common/as_entry.h"
#include "common/info_field.h"
#include "data_plane/packet.h"
#include "data_plane/scmp.h"
#include "data_plane/udp.h"
#include "test_serialization.h"
#include "util/list.h"

int scion_test_serialize_udp(void)
{
	struct scion_udp udp;
	udp.src_port = 31337;
	udp.dst_port = 31000;
	udp.data_length = 0;
	udp.data = NULL;

	uint16_t buf_len = 8;
	uint8_t buf[buf_len];
	int ret = scion_udp_serialize(&udp, buf, &buf_len);
	if (ret != 0) {
		return ret;
	}

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

	return (memcmp(&buf, &test_buf, sizeof(buf)) != 0);
}

int scion_test_serialize_meta_hdr(void)
{
	struct scion_path_meta_hdr hdr;
	hdr.curr_inf = 2;
	hdr.curr_hf = 7;
	hdr.seg_len[0] = 3;
	hdr.seg_len[1] = 3;
	hdr.seg_len[2] = 4;

	uint8_t buf[4];
	int ret = scion_path_meta_hdr_serialize(&hdr, buf);
	if (ret != 0) {
		return ret;
	}

	const uint8_t test_buf[] = {
		0x87,
		0x00,
		0x30,
		0xc4,
	};

	return (memcmp(&buf, &test_buf, sizeof(buf)) != 0);
}

int scion_test_serialize_info_field(void)
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

	return (memcmp(&buf, &test_buf, sizeof(buf)) != 0);
}

int scion_test_serialize_hop_field(void)
{
	struct scion_hop_field hop_field;
	hop_field.ingress_router_alert = false;
	hop_field.egress_router_alert = false;
	hop_field.exp_time = 63;
	hop_field.cons_ingress = 301;
	hop_field.cons_egress = 0;
	hop_field.mac[0] = 0x60;
	hop_field.mac[1] = 0xe4;
	hop_field.mac[2] = 0xba;
	hop_field.mac[3] = 0xd9;
	hop_field.mac[4] = 0xf1;
	hop_field.mac[5] = 0xbe;

	uint8_t buf[12];
	scion_hop_field_serialize((uint8_t *)&buf, &hop_field);

	const uint8_t test_buf[] = {
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

	return (memcmp(&buf, &test_buf, sizeof(buf)) != 0);
}

int scion_test_serialize_path(void)
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

	if (ret != 0) {
		return ret;
	}

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

	return (memcmp(&buf, &test_buf, sizeof(buf)) != 0);
}

int scion_test_serialize_scion_packet(void)
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
	if (ret < SCION_UDP_HDR_LEN) {
		free(packet.raw_dst_addr);
		free(packet.raw_src_addr);
		free(packet.payload);
		return ret;
	}

	size_t packet_length = scion_packet_len(&packet);
	uint8_t *packet_buf = malloc(packet_length);

	ret = scion_packet_serialize(&packet, packet_buf, &packet_length);
	if (ret < 0) {
		free(packet.raw_dst_addr);
		free(packet.raw_src_addr);
		free(packet.payload);
		free(packet_buf);
		return ret;
	}

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
        0x79, 0x18, 0x79, 0x18, 0x00, 0x0b, 0x48, 0xda,
        0x61, 0x62, 0x63,
	};
	// clang-format on

	ret = (memcmp(packet_buf, &test_buf, packet_length) != 0);

	free(packet.raw_dst_addr);
	free(packet.raw_src_addr);
	free(packet.payload);
	free(packet_buf);

	return ret;
}

int scion_test_serialize_scmp_echo(void)
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

	int ret = scion_scmp_echo_serialize(&echo, buf, buf_len);
	if (ret != 16) {
		return ret;
	}

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

	return (memcmp(&buf, &test_buf, sizeof(buf)) != 0);
}
