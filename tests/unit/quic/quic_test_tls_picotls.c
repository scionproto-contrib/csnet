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

// TLS of the test server with picotls and mbedTLS: the certificate is loaded with ptls_load_certificates(), the
// handshake is signed (ECDSA P-256) with mbedtls_pk_sign().

#include <stdlib.h>
#include <string.h>

#include <picotls.h>
#include <picotls/mbedtls.h>
#include <picotls/pembase64.h>

#include <ngtcp2/ngtcp2_crypto_picotls.h>

#include <mbedtls/pk.h>
#include <psa/crypto.h>

#include "quic_test_server.h"

struct signer {
	ptls_sign_certificate_t super; // must be first
	mbedtls_pk_context key;
};

struct quic_test_tls {
	ptls_context_t ctx;
	ptls_on_client_hello_t on_client_hello;
	struct signer signer;
};

struct session {
	ngtcp2_crypto_picotls_ctx cptls;
	ptls_raw_extension_t extensions[2];
};

static ptls_key_exchange_algorithm_t *key_exchanges[] = { &ptls_mbedtls_x25519, &ptls_mbedtls_secp256r1, NULL };
static ptls_cipher_suite_t *cipher_suites[] = { &ptls_mbedtls_aes128gcmsha256, &ptls_mbedtls_chacha20poly1305sha256,
	NULL };

static int sign(ptls_sign_certificate_t *self, ptls_t *tls, ptls_async_job_t **async, uint16_t *selected_algorithm,
	ptls_buffer_t *output, ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms)
{
	struct signer *signer = (struct signer *)self;
	uint8_t hash[32], sig[MBEDTLS_PK_SIGNATURE_MAX_SIZE];
	size_t hash_len, sig_len;
	int ret;
	(void)tls;
	(void)async;

	for (size_t i = 0;; i++) {
		if (i == num_algorithms) {
			return PTLS_ALERT_HANDSHAKE_FAILURE;
		}
		if (algorithms[i] == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256) {
			break;
		}
	}
	if (psa_hash_compute(PSA_ALG_SHA_256, input.base, input.len, hash, sizeof(hash), &hash_len) != PSA_SUCCESS
		|| mbedtls_pk_sign(&signer->key, MBEDTLS_MD_SHA256, hash, hash_len, sig, sizeof(sig), &sig_len) != 0) {
		return PTLS_ERROR_LIBRARY;
	}
	*selected_algorithm = PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256;
	ptls_buffer_pushv(output, sig, sig_len);
	ret = 0;
Exit:
	return ret;
}

static int on_client_hello(ptls_on_client_hello_t *self, ptls_t *tls, ptls_on_client_hello_parameters_t *params)
{
	(void)self;
	for (size_t i = 0; i < params->negotiated_protocols.count; i++) {
		ptls_iovec_t proto = params->negotiated_protocols.list[i];
		if (proto.len == strlen(QUIC_TEST_ALPN) && memcmp(proto.base, QUIC_TEST_ALPN, proto.len) == 0) {
			return ptls_set_negotiated_protocol(tls, (const char *)proto.base, proto.len);
		}
	}
	return PTLS_ALERT_NO_APPLICATION_PROTOCOL;
}

struct quic_test_tls *quic_test_tls_new(void)
{
	struct quic_test_tls *tls = calloc(1, sizeof(*tls));
	size_t key_len;
	char *key = quic_test_read_file("server.key", &key_len);

	if (!tls || !key || psa_crypto_init() != PSA_SUCCESS) {
		goto fail;
	}
	mbedtls_pk_init(&tls->signer.key);
	if (mbedtls_pk_parse_key(&tls->signer.key, (const unsigned char *)key, key_len + 1, NULL, 0) != 0) {
		goto fail;
	}
	tls->signer.super.cb = sign;
	tls->on_client_hello.cb = on_client_hello;
	tls->ctx.random_bytes = ptls_mbedtls_random_bytes;
	tls->ctx.get_time = &ptls_get_time;
	tls->ctx.key_exchanges = key_exchanges;
	tls->ctx.cipher_suites = cipher_suites;
	tls->ctx.sign_certificate = &tls->signer.super;
	tls->ctx.on_client_hello = &tls->on_client_hello;
	tls->ctx.require_dhe_on_psk = 1;
	if (ptls_load_certificates(&tls->ctx, QUIC_TEST_DATA_DIR "/server.pem") != 0
		|| ngtcp2_crypto_picotls_configure_server_context(&tls->ctx) != 0) {
		goto fail;
	}
	free(key);
	return tls;

fail:
	free(key);
	quic_test_tls_free(tls);
	return NULL;
}

void quic_test_tls_free(struct quic_test_tls *tls)
{
	if (!tls) {
		return;
	}
	for (size_t i = 0; i < tls->ctx.certificates.count; i++) {
		free(tls->ctx.certificates.list[i].base);
	}
	free(tls->ctx.certificates.list);
	mbedtls_pk_free(&tls->signer.key);
	free(tls);
}

void *quic_test_tls_session_new(struct quic_test_tls *tls, ngtcp2_crypto_conn_ref *conn_ref, void **native_handle)
{
	struct session *s = calloc(1, sizeof(*s));
	if (!s) {
		return NULL;
	}
	ngtcp2_crypto_picotls_ctx_init(&s->cptls);
	if (!(s->cptls.ptls = ptls_server_new(&tls->ctx))) {
		free(s);
		return NULL;
	}
	*ptls_get_data_ptr(s->cptls.ptls) = conn_ref;
	s->extensions[0].type = UINT16_MAX;
	s->extensions[1].type = UINT16_MAX;
	s->cptls.handshake_properties.additional_extensions = s->extensions;
	if (ngtcp2_crypto_picotls_configure_server_session(&s->cptls) != 0) {
		quic_test_tls_session_free(s);
		return NULL;
	}
	*native_handle = &s->cptls;
	return s;
}

int quic_test_tls_session_attach(void *session, ngtcp2_conn *conn)
{
	(void)session;
	(void)conn;
	return 0;
}

void quic_test_tls_session_free(void *session)
{
	struct session *s = session;
	if (!s) {
		return;
	}
	ngtcp2_crypto_picotls_deconfigure_session(&s->cptls);
	ptls_free(s->cptls.ptls);
	free(s);
}

void quic_test_tls_random(uint8_t *buf, size_t len)
{
	ptls_mbedtls_random_bytes(buf, len);
}
