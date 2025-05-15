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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/as_entry.h"
#include "common/info_field.h"
#include "data_plane/packet.h"
#include "data_plane/socket.h"
#include "data_plane/udp.h"
#include "test_deserialization.h"

int scion_test_deserialize_udp(void)
{
	int ret = 0;

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

	ret = scion_udp_deserialize(buf, 8, &udp);
	if (ret != 0) {
		return ret;
	}

	if (udp.src_port != 31337) {
		ret = 1;
	} else if (udp.dst_port != 31000) {
		ret = 2;
	} else if (udp.data_length != 0) {
		ret = 3;
	} else if (udp.data != NULL) {
		ret = 5;
	}

	return ret;
}

int scion_test_deserialize_meta_hdr(void)
{
	int ret = 0;

	struct scion_path_meta_hdr hdr;

	const uint8_t buf[] = {
		0x87,
		0x00,
		0x30,
		0xc4,
	};

	ret = scion_path_meta_hdr_deserialize((uint8_t *)&buf, &hdr);

	if (ret != 0) {
		return ret;
	}

	if (hdr.curr_inf != 2) {
		ret = 1;
	} else if (hdr.curr_hf != 7) {
		ret = 2;
	} else if (hdr.seg_len[0] != 3) {
		ret = 3;
	} else if (hdr.seg_len[1] != 3) {
		ret = 4;
	} else if (hdr.seg_len[2] != 4) {
		ret = 5;
	}

	return ret;
}

int scion_test_deserialize_info_field(void)
{
	int ret = 0;

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

	ret = scion_info_field_deserialize((uint8_t *)&buf, &info_field);
	if (ret != 0) {
		return ret;
	}

	if (info_field.peer != false) {
		ret = 1;
	} else if (info_field.cons_dir != true) {
		ret = 2;
	} else if (info_field.seg_id != 0x3bfa) {
		ret = 3;
	} else if (info_field.timestamp != 1731596031) {
		ret = 4;
	}

	return ret;
}

int scion_test_deserialize_hop_field(void)
{
	int ret = 0;

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

	ret = scion_hop_field_deserialize((uint8_t *)&buf, &hop_field);
	if (ret != 0) {
		return ret;
	}

	if (hop_field.ingress_router_alert != false) {
		ret = 1;
	} else if (hop_field.egress_router_alert != false) {
		ret = 2;
	} else if (hop_field.exp_time != 63) {
		ret = 3;
	} else if (hop_field.cons_ingress != 301) {
		ret = 4;
	} else if (hop_field.cons_egress != 0) {
		ret = 5;
	} else if (memcmp(&hop_field.mac, &mac, sizeof(mac)) != 0) {
		ret = 6;
	}

	return ret;
}

int scion_test_deserialize_path(void)
{
	// Path from AS 221 to AS 121 in the test topology

	int ret = 0;

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
	struct scion_linked_list *info_fields = scion_list_create(SCION_LIST_SIMPLE_FREE);
	struct scion_linked_list *hop_fields = scion_list_create(SCION_LIST_SIMPLE_FREE);

	ret = scion_path_deserialize((uint8_t *)&buf, &hdr, info_fields, hop_fields);
	if (ret != 0) {
		return ret;
	}

	if (hdr.curr_inf != 2) {
		ret = 1;
	} else if (hdr.curr_hf != 5) {
		ret = 2;
	} else if (hdr.seg_len[0] != 2) {
		ret = 3;
	} else if (hdr.seg_len[1] != 2) {
		ret = 4;
	} else if (hdr.seg_len[2] != 2) {
		ret = 5;
	}

	if (info_fields->size != 3) {
		ret = 10;
	} else if (hop_fields->size != 6) {
		ret = 100;
	}

	if (ret != 0) {
		scion_list_free(info_fields);
		scion_list_free(hop_fields);
		return ret;
	}

	// Info Fields
	struct scion_linked_list_node *curr = info_fields->first;
	struct scion_info_field *curr_if = (struct scion_info_field *)curr->value;

	if (curr_if == NULL) {
		ret = 11;
	} else if (curr_if->peer != false) {
		ret = 12;
	} else if (curr_if->cons_dir != false) {
		ret = 13;
	} else if (curr_if->seg_id != 0x9890) {
		ret = 14;
	} else if (curr_if->timestamp != 0x67375efc) {
		ret = 15;
	}

	curr = curr->next;
	curr_if = (struct scion_info_field *)curr->value;

	if (curr_if == NULL) {
		ret = 21;
	} else if (curr_if->peer != false) {
		ret = 22;
	} else if (curr_if->cons_dir != false) {
		ret = 23;
	} else if (curr_if->seg_id != 0x8c1d) {
		ret = 24;
	} else if (curr_if->timestamp != 0x67375eb3) {
		ret = 25;
	}

	curr = curr->next;
	curr_if = (struct scion_info_field *)curr->value;

	if (curr_if == NULL) {
		ret = 31;
	} else if (curr_if->peer != false) {
		ret = 32;
	} else if (curr_if->cons_dir != true) {
		ret = 33;
	} else if (curr_if->seg_id != 0xdc39) {
		ret = 34;
	} else if (curr_if->timestamp != 0x67375eae) {
		ret = 35;
	}

	// Hop Fields
	curr = hop_fields->first;
	struct scion_hop_field *curr_hf = (struct scion_hop_field *)curr->value;
	uint8_t mac_0[6] = { 0x87, 0x2d, 0x92, 0x63, 0xd1, 0x97 };
	if (curr_hf == NULL) {
		ret = 101;
	} else if (curr_hf->ingress_router_alert != false) {
		ret = 102;
	} else if (curr_hf->egress_router_alert != false) {
		ret = 103;
	} else if (curr_hf->exp_time != 63) {
		ret = 104;
	} else if (curr_hf->cons_ingress != 2) {
		ret = 105;
	} else if (curr_hf->cons_egress != 0) {
		ret = 106;
	} else if (memcmp(&mac_0, &curr_hf->mac, sizeof(mac_0)) != 0) {
		ret = 107;
	}

	curr = curr->next;
	curr_hf = (struct scion_hop_field *)curr->value;
	uint8_t mac_1[6] = { 0xae, 0xe2, 0x32, 0xfe, 0xe4, 0xdf };
	if (curr_hf == NULL) {
		ret = 111;
	} else if (curr_hf->ingress_router_alert != false) {
		ret = 112;
	} else if (curr_hf->egress_router_alert != false) {
		ret = 113;
	} else if (curr_hf->exp_time != 63) {
		ret = 114;
	} else if (curr_hf->cons_ingress != 0) {
		ret = 115;
	} else if (curr_hf->cons_egress != 500) {
		ret = 116;
	} else if (memcmp(&mac_1, &curr_hf->mac, sizeof(mac_1)) != 0) {
		ret = 117;
	}

	curr = curr->next;
	curr_hf = (struct scion_hop_field *)curr->value;
	uint8_t mac_2[6] = { 0x31, 0x76, 0xc2, 0x99, 0x18, 0xf2 };
	if (curr_hf == NULL) {
		ret = 121;
	} else if (curr_hf->ingress_router_alert != false) {
		ret = 122;
	} else if (curr_hf->egress_router_alert != false) {
		ret = 123;
	} else if (curr_hf->exp_time != 63) {
		ret = 124;
	} else if (curr_hf->cons_ingress != 502) {
		ret = 125;
	} else if (curr_hf->cons_egress != 0) {
		ret = 126;
	} else if (memcmp(&mac_2, &curr_hf->mac, sizeof(mac_2)) != 0) {
		ret = 127;
	}

	curr = curr->next;
	curr_hf = (struct scion_hop_field *)curr->value;
	uint8_t mac_3[6] = { 0xe1, 0x00, 0x16, 0xdf, 0xd5, 0x4b };
	if (curr_hf == NULL) {
		ret = 131;
	} else if (curr_hf->ingress_router_alert != false) {
		ret = 132;
	} else if (curr_hf->egress_router_alert != false) {
		ret = 133;
	} else if (curr_hf->exp_time != 63) {
		ret = 134;
	} else if (curr_hf->cons_ingress != 0) {
		ret = 135;
	} else if (curr_hf->cons_egress != 3) {
		ret = 136;
	} else if (memcmp(&mac_3, &curr_hf->mac, sizeof(mac_3)) != 0) {
		ret = 137;
	}

	curr = curr->next;
	curr_hf = (struct scion_hop_field *)curr->value;
	uint8_t mac_4[6] = { 0x25, 0x66, 0x37, 0x02, 0x8d, 0xda };
	if (curr_hf == NULL) {
		ret = 141;
	} else if (curr_hf->ingress_router_alert != false) {
		ret = 142;
	} else if (curr_hf->egress_router_alert != false) {
		ret = 143;
	} else if (curr_hf->exp_time != 63) {
		ret = 144;
	} else if (curr_hf->cons_ingress != 0) {
		ret = 145;
	} else if (curr_hf->cons_egress != 4) {
		ret = 146;
	} else if (memcmp(&mac_4, &curr_hf->mac, sizeof(mac_4)) != 0) {
		ret = 147;
	}

	curr = curr->next;
	curr_hf = (struct scion_hop_field *)curr->value;
	uint8_t mac_5[6] = { 0x2c, 0xad, 0xf3, 0x51, 0xb8, 0xbd };
	if (curr_hf == NULL) {
		ret = 151;
	} else if (curr_hf->ingress_router_alert != false) {
		ret = 152;
	} else if (curr_hf->egress_router_alert != false) {
		ret = 153;
	} else if (curr_hf->exp_time != 63) {
		ret = 154;
	} else if (curr_hf->cons_ingress != 3) {
		ret = 155;
	} else if (curr_hf->cons_egress != 0) {
		ret = 156;
	} else if (memcmp(&mac_5, &curr_hf->mac, sizeof(mac_5)) != 0) {
		ret = 157;
	}

	scion_list_free(info_fields);
	scion_list_free(hop_fields);

	return ret;
}

int scion_test_deserialize_scion_packet(void)
{
	// Path from AS 221 to AS 121 in the test topology

	int ret = 0;

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
	ret = scion_packet_deserialize(buf, sizeof(buf), &packet);
	if (ret != 0) {
		return ret;
	}

	if (packet.version != 0) {
		ret = 1;
	} else if (packet.traffic_class != 0) {
		ret = 2;
	} else if (packet.flow_id != 1) {
		ret = 3;
	} else if (packet.next_hdr != SCION_PROTO_UDP) {
		ret = 4;
	} else if (packet.payload_len != 11) {
		ret = 6;
	} else if (packet.path_type != SCION_PATH_TYPE_SCION) {
		ret = 7;
	} else if (packet.dst_addr_type != SCION_ADDR_TYPE_T4IP) {
		ret = 8;
	} else if (packet.src_addr_type != SCION_ADDR_TYPE_T4IP) {
		ret = 9;
	} else if (packet.dst_ia != 0x1ff0000000121) {
		ret = 10;
	} else if (packet.src_ia != 0x2ff0000000221) {
		ret = 11;
	} else if (packet.raw_dst_addr_length != 4) {
		ret = 12;
	} else if (memcmp(&dst_host, packet.raw_dst_addr, packet.raw_dst_addr_length) != 0) {
		ret = 13;
	} else if (packet.raw_src_addr_length != 4) {
		ret = 14;
	} else if (memcmp(&src_host, packet.raw_src_addr, packet.raw_src_addr_length) != 0) {
		ret = 15;
	} else if (packet.path->raw_path->length != sizeof(path_buf)) {
		ret = 16;
	} else if (memcmp(&path_buf, packet.path->raw_path->raw, sizeof(path_buf)) != 0) {
		ret = 17;
	} else if (memcmp(&udp_buf, packet.payload, sizeof(udp_buf)) != 0) {
		ret = 18;
	}

	free(packet.raw_dst_addr);
	free(packet.raw_src_addr);
	free(packet.path->raw_path->raw);
	free(packet.path->raw_path);
	free(packet.path);
	free(packet.payload);

	return ret;
}
