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

#include "control_plane/pki/trc.h"
#include "test_trc.h"

// The fixtures come from the default topology of scion-testnet, generated on 2026-11-11 15:14:24: the TRCs of ISD 1
// and 2, the certificate chain of 1-ff00:0:133 and a message signed with the key of its AS certificate (ECDSA with
// SHA-256). The AS certificate is valid until 2026-12-09 15:15:24, the other certificates and the TRCs until 2028.

// The TRC updates come from a test ISD with the core ASes 1-ff00:0:110 and 1-ff00:0:120, generated with scion-pki
// testcrypto and updated with its scenarios: S2 is a regular update that changes the root and regular voting
// certificates, S3 a regular update that changes none, and S4 a sensitive update that changes all of them. The other
// updates are signed and combined with scion-pki trc: S2 without the acknowledgments of the changed root certificates,
// and S4 with the vote of only one of the two sensitive voters that it lists.

struct fixture {
	const char *name;
	uint8_t data[8192];
	size_t len;
};

static struct fixture trc_isd1 = { .name = "ISD1-B1-S1.trc" };
static struct fixture trc_isd2 = { .name = "ISD2-B1-S1.trc" };
static struct fixture as_cert = { .name = "ISD1-ASff00_0_133.as.crt" };
static struct fixture update_s1 = { .name = "updates/ISD1-B1-S1.trc" };
static struct fixture update_s2 = { .name = "updates/ISD1-B1-S2.trc" };
static struct fixture update_s3 = { .name = "updates/ISD1-B1-S3.trc" };
static struct fixture update_s4 = { .name = "updates/ISD1-B1-S4.trc" };
static struct fixture update_s2_no_root_ack = { .name = "updates/ISD1-B1-S2.no-root-ack.trc" };
static struct fixture update_s4_one_vote = { .name = "updates/ISD1-B1-S4.one-vote.trc" };

static int load_fixtures(void **)
{
	struct fixture *fixtures[] = { &trc_isd1, &trc_isd2, &as_cert, &update_s1, &update_s2, &update_s3, &update_s4,
		&update_s2_no_root_ack, &update_s4_one_vote };
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

static void test_trc_parse(void **)
{
	struct scion_trc trc;

	assert_int_equal(scion_trc_parse(trc_isd1.data, trc_isd1.len, &trc), 0);

	assert_int_equal(trc.isd, 1);
	assert_int_equal(trc.base, 1);
	assert_int_equal(trc.serial, 1);
	assert_int_equal(trc.not_before, 1794410064); // 2026-11-11 15:14:24
	assert_int_equal(trc.not_after, 1833290064); // 2028-02-04 15:14:24
	assert_int_equal(trc.grace_period, 0);
	assert_false(trc.no_trust_reset);
	assert_int_equal(trc.quorum, 2);

	// The root certificates of the core ASes 1-ff00:0:110, 1-ff00:0:120 and 1-ff00:0:130
	size_t num_roots = 0;
	for (const mbedtls_x509_crt *root = &trc.roots; root != NULL; root = root->next) {
		num_roots++;
	}
	assert_int_equal(num_roots, 3);

	scion_trc_free_members(&trc);
}

static void test_trc_parse_truncated(void **)
{
	struct scion_trc trc;

	assert_int_equal(scion_trc_parse(trc_isd1.data, trc_isd1.len - 1, &trc), SCION_ERR_TRC_INVALID);
}

static void test_trc_parse_certificate(void **)
{
	struct scion_trc trc;

	assert_int_equal(scion_trc_parse(as_cert.data, as_cert.len, &trc), SCION_ERR_TRC_INVALID);
}

static void test_trc_verify_update_regular(void **)
{
	struct scion_trc s1;
	struct scion_trc s2;
	struct scion_trc s3;
	assert_int_equal(scion_trc_parse(update_s1.data, update_s1.len, &s1), 0);
	assert_int_equal(scion_trc_parse(update_s2.data, update_s2.len, &s2), 0);
	assert_int_equal(scion_trc_parse(update_s3.data, update_s3.len, &s3), 0);

	assert_int_equal(scion_trc_verify_update(&s2, &s1), 0);
	assert_int_equal(scion_trc_verify_update(&s3, &s2), 0);

	scion_trc_free_members(&s3);
	scion_trc_free_members(&s2);
	scion_trc_free_members(&s1);
}

static void test_trc_verify_update_sensitive(void **)
{
	struct scion_trc s3;
	struct scion_trc s4;
	assert_int_equal(scion_trc_parse(update_s3.data, update_s3.len, &s3), 0);
	assert_int_equal(scion_trc_parse(update_s4.data, update_s4.len, &s4), 0);

	assert_int_equal(scion_trc_verify_update(&s4, &s3), 0);

	scion_trc_free_members(&s4);
	scion_trc_free_members(&s3);
}

static void test_trc_verify_update_not_successor(void **)
{
	struct scion_trc s1;
	struct scion_trc s2;
	struct scion_trc s3;
	struct scion_trc other_isd;
	assert_int_equal(scion_trc_parse(update_s1.data, update_s1.len, &s1), 0);
	assert_int_equal(scion_trc_parse(update_s2.data, update_s2.len, &s2), 0);
	assert_int_equal(scion_trc_parse(update_s3.data, update_s3.len, &s3), 0);
	assert_int_equal(scion_trc_parse(trc_isd2.data, trc_isd2.len, &other_isd), 0);

	assert_int_equal(scion_trc_verify_update(&s3, &s1), SCION_ERR_TRC_INVALID);
	assert_int_equal(scion_trc_verify_update(&s1, &s2), SCION_ERR_TRC_INVALID);
	assert_int_equal(scion_trc_verify_update(&s2, &other_isd), SCION_ERR_TRC_INVALID);

	scion_trc_free_members(&other_isd);
	scion_trc_free_members(&s3);
	scion_trc_free_members(&s2);
	scion_trc_free_members(&s1);
}

static void test_trc_verify_update_missing_root_ack(void **)
{
	struct scion_trc s1;
	struct scion_trc s2;
	assert_int_equal(scion_trc_parse(update_s1.data, update_s1.len, &s1), 0);
	assert_int_equal(scion_trc_parse(update_s2_no_root_ack.data, update_s2_no_root_ack.len, &s2), 0);

	assert_int_equal(scion_trc_verify_update(&s2, &s1), SCION_ERR_TRC_INVALID);

	scion_trc_free_members(&s2);
	scion_trc_free_members(&s1);
}

static void test_trc_verify_update_missing_vote(void **)
{
	struct scion_trc s3;
	struct scion_trc s4;
	assert_int_equal(scion_trc_parse(update_s3.data, update_s3.len, &s3), 0);
	assert_int_equal(scion_trc_parse(update_s4_one_vote.data, update_s4_one_vote.len, &s4), 0);

	assert_int_equal(scion_trc_verify_update(&s4, &s3), SCION_ERR_TRC_INVALID);

	scion_trc_free_members(&s4);
	scion_trc_free_members(&s3);
}

// The last byte of the TRC is the last byte of the signature of its last signer
static void test_trc_verify_update_invalid_signature(void **)
{
	uint8_t tampered[sizeof(update_s2.data)];
	(void)memcpy(tampered, update_s2.data, update_s2.len);
	tampered[update_s2.len - 1] ^= 1;
	struct scion_trc s1;
	struct scion_trc s2;
	assert_int_equal(scion_trc_parse(update_s1.data, update_s1.len, &s1), 0);
	assert_int_equal(scion_trc_parse(tampered, update_s2.len, &s2), 0);

	assert_int_equal(scion_trc_verify_update(&s2, &s1), SCION_ERR_TRC_INVALID);

	scion_trc_free_members(&s2);
	scion_trc_free_members(&s1);
}

int run_trc_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_trc_parse),
		cmocka_unit_test(test_trc_parse_truncated),
		cmocka_unit_test(test_trc_parse_certificate),
		cmocka_unit_test(test_trc_verify_update_regular),
		cmocka_unit_test(test_trc_verify_update_sensitive),
		cmocka_unit_test(test_trc_verify_update_not_successor),
		cmocka_unit_test(test_trc_verify_update_missing_root_ack),
		cmocka_unit_test(test_trc_verify_update_missing_vote),
		cmocka_unit_test(test_trc_verify_update_invalid_signature),
	};

	return cmocka_run_group_tests(tests, load_fixtures, NULL);
}
