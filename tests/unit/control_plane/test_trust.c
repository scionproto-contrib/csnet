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
#include <stdio.h>
#include <string.h>

#include "control_plane/network.h"
#include "control_plane/trust.h"
#include "test_trust.h"

// The TRCs are the ones of the test fixtures of test_cppki.c, ISD 1 in PEM and ISD 2 in DER. The directory also has a
// certificate, which is not loaded as it is not a .trc file.
#define TRC_DIR TEST_TOPOLOGY_DATA_DIR "/trcs"
#define INVALID_TRC_DIR TEST_TOPOLOGY_DATA_DIR "/trcs_invalid"

// 2026-11-20, when the certificates of the chain of 1-ff00:0:133 are valid
#define VALID_TIME ((time_t)1795132800)
// 2026-12-10, after its AS certificate expired
#define EXPIRED_TIME ((time_t)1796860800)

struct fixture {
	const char *name;
	uint8_t data[2048];
	size_t len;
};

static struct fixture as_cert = { .name = "ISD1-ASff00_0_133.as.crt" };
static struct fixture ca_cert = { .name = "ISD1-ASff00_0_133.ca.crt" };

static int load_fixtures(void **)
{
	struct fixture *fixtures[] = { &as_cert, &ca_cert };
	for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++) {
		char path[512];
		(void)snprintf(path, sizeof(path), "%s/%s", TEST_CPPKI_DATA_DIR, fixtures[i]->name);
		FILE *file = fopen(path, "rb");
		if (file == NULL) {
			return -1;
		}
		fixtures[i]->len = fread(fixtures[i]->data, 1, sizeof(fixtures[i]->data), file);
		(void)fclose(file);
	}

	return 0;
}

static void test_load_trcs(void **)
{
	struct scion_network net = { 0 };

	assert_int_equal(scion_network_load_trcs(&net, TRC_DIR), 0);

	assert_int_equal(net.trcs->num_trcs, 2);
	assert_int_equal(net.trcs->trcs[0].isd + net.trcs->trcs[1].isd, 1 + 2);

	scion_network_free_trcs(&net);
}

static void test_load_trcs_twice(void **)
{
	struct scion_network net = { 0 };

	assert_int_equal(scion_network_load_trcs(&net, TRC_DIR), 0);
	assert_int_equal(scion_network_load_trcs(&net, TRC_DIR), 0);

	assert_int_equal(net.trcs->num_trcs, 2);

	scion_network_free_trcs(&net);
}

static void test_load_trcs_missing_dir(void **)
{
	struct scion_network net = { 0 };

	assert_int_equal(scion_network_load_trcs(&net, TEST_TOPOLOGY_DATA_DIR "/missing"), SCION_ERR_FILE_NOT_FOUND);

	assert_null(net.trcs);
}

static void test_load_trcs_invalid(void **)
{
	struct scion_network net = { 0 };

	assert_int_equal(scion_network_load_trcs(&net, INVALID_TRC_DIR), SCION_ERR_TRC_INVALID);

	assert_null(net.trcs);
}

static void test_verify_chain(void **)
{
	struct scion_network net = { 0 };
	struct scion_cert_chain chain;
	assert_int_equal(scion_network_load_trcs(&net, TRC_DIR), 0);
	assert_int_equal(scion_cert_chain_parse(as_cert.data, as_cert.len, ca_cert.data, ca_cert.len, &chain), 0);

	assert_int_equal(scion_network_verify_chain(&net, &chain, VALID_TIME), 0);
	assert_int_equal(scion_network_verify_chain(&net, &chain, EXPIRED_TIME), SCION_ERR_CERT_CHAIN_UNVERIFIED);

	scion_cert_chain_free_members(&chain);
	scion_network_free_trcs(&net);
}

static void test_verify_chain_without_trcs(void **)
{
	struct scion_network net = { 0 };
	struct scion_cert_chain chain;
	assert_int_equal(scion_cert_chain_parse(as_cert.data, as_cert.len, ca_cert.data, ca_cert.len, &chain), 0);

	assert_int_equal(scion_network_verify_chain(&net, &chain, VALID_TIME), SCION_ERR_CERT_CHAIN_UNVERIFIED);

	scion_cert_chain_free_members(&chain);
}

// A network that has the TRC that a signer refers to does not ask the control service for it
static void test_update_trcs_up_to_date(void **)
{
	struct scion_network net = { 0 };
	assert_int_equal(scion_network_load_trcs(&net, TRC_DIR), 0);

	assert_int_equal(scion_network_update_trcs(&net, 1, 1, 1, VALID_TIME), 0);

	assert_int_equal(net.trcs->num_trcs, 2);

	scion_network_free_trcs(&net);
}

static void test_update_trcs_trust_reset(void **)
{
	struct scion_network net = { 0 };
	assert_int_equal(scion_network_load_trcs(&net, TRC_DIR), 0);

	assert_int_equal(scion_network_update_trcs(&net, 1, 2, 2, VALID_TIME), SCION_ERR_TRC_INVALID);
	assert_int_equal(scion_network_update_trcs(&net, 3, 1, 2, VALID_TIME), SCION_ERR_TRC_INVALID);

	assert_int_equal(net.trcs->num_trcs, 2);

	scion_network_free_trcs(&net);
}

static void test_update_trcs_without_trcs(void **)
{
	struct scion_network net = { 0 };

	assert_int_equal(scion_network_update_trcs(&net, 1, 1, 2, VALID_TIME), SCION_ERR_TRC_INVALID);
}

int run_trust_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_load_trcs),
		cmocka_unit_test(test_load_trcs_twice),
		cmocka_unit_test(test_load_trcs_missing_dir),
		cmocka_unit_test(test_load_trcs_invalid),
		cmocka_unit_test(test_verify_chain),
		cmocka_unit_test(test_verify_chain_without_trcs),
		cmocka_unit_test(test_update_trcs_up_to_date),
		cmocka_unit_test(test_update_trcs_trust_reset),
		cmocka_unit_test(test_update_trcs_without_trcs),
	};

	return cmocka_run_group_tests(tests, load_fixtures, NULL);
}
