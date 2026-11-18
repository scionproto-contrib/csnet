// Copyright 2025 ETH Zurich
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

#include "control_plane/pki/cert_chain.h"
#include "test_cert_chain.h"

// The fixtures come from the default topology of scion-testnet, generated on 2026-11-11 15:14:24: the TRCs of ISD 1
// and 2, the certificate chain of 1-ff00:0:133 and a message signed with the key of its AS certificate (ECDSA with
// SHA-256). The AS certificate is valid until 2026-12-09 15:15:24, the other certificates and the TRCs until 2028.

// 2026-11-20
#define VALID_TIME ((time_t)1795132800)
// 2026-12-10
#define EXPIRED_TIME ((time_t)1796860800)
// 2026-11-11 15:00
#define EARLY_TIME ((time_t)1794409200)

struct fixture {
	const char *name;
	uint8_t data[8192];
	size_t len;
};

static struct fixture trc_isd1 = { .name = "ISD1-B1-S1.trc" };
static struct fixture trc_isd2 = { .name = "ISD2-B1-S1.trc" };
static struct fixture as_cert = { .name = "ISD1-ASff00_0_133.as.crt" };
static struct fixture ca_cert = { .name = "ISD1-ASff00_0_133.ca.crt" };
static struct fixture message = { .name = "message" };
static struct fixture signature = { .name = "message.sig" };

static int load_fixtures(void **)
{
	struct fixture *fixtures[] = { &trc_isd1, &trc_isd2, &as_cert, &ca_cert, &message, &signature };
	for (size_t i = 0; i < sizeof(fixtures) / sizeof(fixtures[0]); i++) {
		char path[512];
		(void)snprintf(path, sizeof(path), "%s/%s", TEST_PKI_DATA_DIR, fixtures[i]->name);
		FILE *file = fopen(path, "rb");
		if (file == NULL) {
			return -1;
		}
		fixtures[i]->len = fread(fixtures[i]->data, 1, sizeof(fixtures[i]->data), file);
		(void)fclose(file);
	}

	return 0;
}

static void test_cert_chain_parse(void **)
{
	struct scion_cert_chain chain;

	assert_int_equal(scion_cert_chain_parse(as_cert.data, as_cert.len, ca_cert.data, ca_cert.len, &chain), 0);

	assert_true(chain.ia == 0x1ff0000000133);

	scion_cert_chain_free_members(&chain);
}

static void test_cert_chain_parse_swapped(void **)
{
	struct scion_cert_chain chain;

	assert_int_equal(
		scion_cert_chain_parse(ca_cert.data, ca_cert.len, as_cert.data, as_cert.len, &chain), SCION_ERR_CERT_INVALID);
}

static void test_cert_chain_verify(void **)
{
	struct scion_trc trc;
	struct scion_cert_chain chain;
	assert_int_equal(scion_trc_parse(trc_isd1.data, trc_isd1.len, &trc), 0);
	assert_int_equal(scion_cert_chain_parse(as_cert.data, as_cert.len, ca_cert.data, ca_cert.len, &chain), 0);

	assert_int_equal(scion_cert_chain_verify(&chain, &trc, VALID_TIME), 0);
	assert_int_equal(scion_cert_chain_verify(&chain, &trc, EXPIRED_TIME), SCION_ERR_CERT_CHAIN_UNVERIFIED);
	assert_int_equal(scion_cert_chain_verify(&chain, &trc, EARLY_TIME), SCION_ERR_CERT_CHAIN_UNVERIFIED);

	scion_cert_chain_free_members(&chain);
	scion_trc_free_members(&trc);
}

static void test_cert_chain_verify_other_isd(void **)
{
	struct scion_trc trc;
	struct scion_cert_chain chain;
	assert_int_equal(scion_trc_parse(trc_isd2.data, trc_isd2.len, &trc), 0);
	assert_int_equal(scion_cert_chain_parse(as_cert.data, as_cert.len, ca_cert.data, ca_cert.len, &chain), 0);

	assert_int_equal(scion_cert_chain_verify(&chain, &trc, VALID_TIME), SCION_ERR_CERT_CHAIN_UNVERIFIED);

	scion_cert_chain_free_members(&chain);
	scion_trc_free_members(&trc);
}

// The message is signed in two parts, as a signature of the control plane covers the signed message and the data that
// is associated with it.
static void test_cert_chain_verify_signature(void **)
{
	struct scion_cert_chain chain;
	assert_int_equal(scion_cert_chain_parse(as_cert.data, as_cert.len, ca_cert.data, ca_cert.len, &chain), 0);
	struct iovec parts[] = { { .iov_base = message.data, .iov_len = 5 },
		{ .iov_base = message.data + 5, .iov_len = message.len - 5 } };

	assert_int_equal(scion_cert_chain_verify_signature(
						 &chain, SCION_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA256, parts, 2, signature.data, signature.len),
		0);

	scion_cert_chain_free_members(&chain);
}

static void test_cert_chain_verify_signature_other_message(void **)
{
	struct scion_cert_chain chain;
	assert_int_equal(scion_cert_chain_parse(as_cert.data, as_cert.len, ca_cert.data, ca_cert.len, &chain), 0);
	struct iovec part = { .iov_base = message.data, .iov_len = message.len - 1 };

	assert_int_equal(scion_cert_chain_verify_signature(
						 &chain, SCION_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA256, &part, 1, signature.data, signature.len),
		SCION_ERR_SIGNATURE_INVALID);

	scion_cert_chain_free_members(&chain);
}

static void test_cert_chain_verify_signature_other_algorithm(void **)
{
	struct scion_cert_chain chain;
	assert_int_equal(scion_cert_chain_parse(as_cert.data, as_cert.len, ca_cert.data, ca_cert.len, &chain), 0);
	struct iovec part = { .iov_base = message.data, .iov_len = message.len };

	assert_int_equal(scion_cert_chain_verify_signature(
						 &chain, SCION_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA384, &part, 1, signature.data, signature.len),
		SCION_ERR_SIGNATURE_INVALID);

	scion_cert_chain_free_members(&chain);
}

int run_cert_chain_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_cert_chain_parse),
		cmocka_unit_test(test_cert_chain_parse_swapped),
		cmocka_unit_test(test_cert_chain_verify),
		cmocka_unit_test(test_cert_chain_verify_other_isd),
		cmocka_unit_test(test_cert_chain_verify_signature),
		cmocka_unit_test(test_cert_chain_verify_signature_other_message),
		cmocka_unit_test(test_cert_chain_verify_signature_other_algorithm),
	};

	return cmocka_run_group_tests(tests, load_fixtures, NULL);
}
