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
#include <string.h>

#include "common/hop_field.h"
#include "test_hop_field.h"

static void test_serialize_hop_field(void **)
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

	assert_memory_equal(buf, test_buf, sizeof(buf));
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

static void test_hop_field_router_alerts(void **)
{
	const struct {
		bool ingress;
		bool egress;
		uint8_t flags;
	} cases[] = { { false, false, 0x00 }, { false, true, 0x01 }, { true, false, 0x02 }, { true, true, 0x03 } };

	for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
		struct scion_hop_field hop_field = { .ingress_router_alert = cases[i].ingress,
			.egress_router_alert = cases[i].egress };

		uint8_t buf[SCION_HOP_LEN];
		scion_hop_field_serialize(buf, &hop_field);
		assert_uint_equal(buf[0], cases[i].flags);

		struct scion_hop_field parsed;
		scion_hop_field_deserialize(buf, &parsed);
		assert_int_equal(parsed.ingress_router_alert, cases[i].ingress);
		assert_int_equal(parsed.egress_router_alert, cases[i].egress);
	}
}

static void test_hop_field_round_trip_extremes(void **)
{
	struct scion_hop_field hop_field = { .exp_time = UINT8_MAX, .cons_ingress = UINT16_MAX, .cons_egress = UINT16_MAX };
	memset(hop_field.mac, 0xff, SCION_MAC_LEN);

	uint8_t buf[SCION_HOP_LEN];
	scion_hop_field_serialize(buf, &hop_field);

	struct scion_hop_field parsed;
	scion_hop_field_deserialize(buf, &parsed);
	assert_uint_equal(parsed.exp_time, UINT8_MAX);
	assert_uint_equal(parsed.cons_ingress, UINT16_MAX);
	assert_uint_equal(parsed.cons_egress, UINT16_MAX);
	assert_memory_equal(parsed.mac, hop_field.mac, SCION_MAC_LEN);
}

int run_hop_field_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_serialize_hop_field),
		cmocka_unit_test(test_deserialize_hop_field),
		cmocka_unit_test(test_hop_field_router_alerts),
		cmocka_unit_test(test_hop_field_round_trip_extremes),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
