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

// TLS backend: picotls (TLS 1.3 handshake, QUIC API) with mbedTLS (cryptography through PSA, X.509).
//
// picotls has no certificate verification for its mbedTLS binding, so the server certificate is verified here with
// mbedtls_x509_crt_verify() (chain, validity, name) and the handshake signature with mbedtls_pk_verify_ext().

#include <stdlib.h>
#include <string.h>

#include <picotls.h>
#include <picotls/mbedtls.h>

#include <ngtcp2/ngtcp2_crypto_picotls.h>

#include <mbedtls/pk.h>
#include <mbedtls/x509_crt.h>
#include <psa/crypto.h>

#include "tls.h"

struct verifier {
	ptls_verify_certificate_t super; // must be first
	mbedtls_x509_crt ca;
};

struct scion_quic_tls {
	ptls_context_t ctx;
	ngtcp2_crypto_picotls_ctx cptls;
	ptls_raw_extension_t extensions[2];
	ptls_iovec_t alpn;
	uint8_t alpn_buf[255];
	struct verifier *verifier;
};

static ptls_key_exchange_algorithm_t *key_exchanges[] = { &ptls_mbedtls_x25519, &ptls_mbedtls_secp256r1, NULL };

static ptls_cipher_suite_t *cipher_suites[] = {
	&ptls_mbedtls_aes128gcmsha256,
#if defined(MBEDTLS_SHA384_C)
	&ptls_mbedtls_aes256gcmsha384,
#endif
	&ptls_mbedtls_chacha20poly1305sha256,
	NULL,
};

// The signature schemes accepted from the server (sent in the signature_algorithms extension).
static const uint16_t signature_algos[] = {
	PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
	PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
	PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
	PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
	PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512,
	UINT16_MAX,
};

// Verifies the CertificateVerify signature with the public key of the server certificate. picotls calls it exactly
// once, with data.base == NULL if the handshake failed before, and the context must be freed in either case.
static int verify_sign(void *verify_ctx, uint16_t algo, ptls_iovec_t data, ptls_iovec_t sign)
{
	mbedtls_x509_crt *chain = verify_ctx;
	mbedtls_pk_sigalg_t sigalg;
	mbedtls_md_type_t md;
	psa_algorithm_t hash_alg;
	uint8_t hash[PSA_HASH_MAX_SIZE];
	size_t hash_len;
	int ret = PTLS_ALERT_DECRYPT_ERROR;

	if (data.base == NULL) {
		ret = 0;
		goto exit;
	}
	switch (algo) {
	case PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256:
		sigalg = MBEDTLS_PK_SIGALG_ECDSA, md = MBEDTLS_MD_SHA256, hash_alg = PSA_ALG_SHA_256;
		break;
	case PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384:
		sigalg = MBEDTLS_PK_SIGALG_ECDSA, md = MBEDTLS_MD_SHA384, hash_alg = PSA_ALG_SHA_384;
		break;
	case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256:
		sigalg = MBEDTLS_PK_SIGALG_RSA_PSS, md = MBEDTLS_MD_SHA256, hash_alg = PSA_ALG_SHA_256;
		break;
	case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384:
		sigalg = MBEDTLS_PK_SIGALG_RSA_PSS, md = MBEDTLS_MD_SHA384, hash_alg = PSA_ALG_SHA_384;
		break;
	case PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512:
		sigalg = MBEDTLS_PK_SIGALG_RSA_PSS, md = MBEDTLS_MD_SHA512, hash_alg = PSA_ALG_SHA_512;
		break;
	default:
		ret = PTLS_ALERT_ILLEGAL_PARAMETER;
		goto exit;
	}
	if (psa_hash_compute(hash_alg, data.base, data.len, hash, sizeof(hash), &hash_len) != PSA_SUCCESS) {
		ret = PTLS_ERROR_LIBRARY;
		goto exit;
	}
	if (mbedtls_pk_verify_ext(sigalg, &chain->pk, md, hash, hash_len, sign.base, sign.len) == 0) {
		ret = 0;
	}

exit:
	mbedtls_x509_crt_free(chain);
	free(chain);
	return ret;
}

// Verifies the certificate chain of the server against the trusted CAs and the server name.
static int verify_certificate(ptls_verify_certificate_t *self, ptls_t *tls, const char *server_name,
	int (**verify_sign_cb)(void *, uint16_t, ptls_iovec_t, ptls_iovec_t), void **verify_data, ptls_iovec_t *certs,
	size_t num_certs)
{
	struct verifier *v = (struct verifier *)self;
	mbedtls_x509_crt *chain;
	uint32_t flags = 0;
	(void)tls;

	if (num_certs == 0) {
		return PTLS_ALERT_CERTIFICATE_REQUIRED;
	}
	if (!(chain = malloc(sizeof(*chain)))) {
		return PTLS_ERROR_NO_MEMORY;
	}
	mbedtls_x509_crt_init(chain);
	for (size_t i = 0; i < num_certs; i++) {
		if (mbedtls_x509_crt_parse_der(chain, certs[i].base, certs[i].len) != 0) {
			goto bad;
		}
	}
	if (mbedtls_x509_crt_verify(chain, &v->ca, NULL, server_name, &flags, NULL, NULL) != 0) {
		goto bad;
	}
	*verify_sign_cb = verify_sign;
	*verify_data = chain; // the leaf certificate is the first one
	return 0;

bad:
	mbedtls_x509_crt_free(chain);
	free(chain);
	return PTLS_ALERT_BAD_CERTIFICATE;
}

static struct verifier *verifier_new(const char *pem, size_t len)
{
	struct verifier *v = calloc(1, sizeof(*v));
	char *buf = malloc(len + 1); // mbedtls_x509_crt_parse() wants PEM data with its terminating NUL
	int ret;

	if (!v || !buf) {
		free(v);
		free(buf);
		return NULL;
	}
	memcpy(buf, pem, len);
	buf[len] = '\0';
	mbedtls_x509_crt_init(&v->ca);
	ret = mbedtls_x509_crt_parse(&v->ca, (const unsigned char *)buf, strlen(buf) + 1);
	free(buf);
	if (ret != 0) { // also > 0: some certificates could not be parsed
		mbedtls_x509_crt_free(&v->ca);
		free(v);
		return NULL;
	}
	v->super.cb = verify_certificate;
	v->super.algos = signature_algos;
	return v;
}

int scion_quic_tls_new(
	struct scion_quic_tls **tls, const struct scion_quic_config *config, ngtcp2_crypto_conn_ref *conn_ref)
{
	size_t alpn_len = strlen(config->alpn);
	struct scion_quic_tls *t;

	if (alpn_len == 0 || alpn_len > sizeof(t->alpn_buf) || psa_crypto_init() != PSA_SUCCESS) {
		return SCION_ERR_TLS_SETUP_FAIL;
	}
	if (!(t = calloc(1, sizeof(*t)))) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}
	t->ctx.random_bytes = ptls_mbedtls_random_bytes;
	t->ctx.get_time = &ptls_get_time;
	t->ctx.key_exchanges = key_exchanges;
	t->ctx.cipher_suites = cipher_suites;
	t->ctx.require_dhe_on_psk = 1;
	if (config->ca_pem) {
		if (!(t->verifier = verifier_new(config->ca_pem, config->ca_pem_len))) {
			goto fail;
		}
		t->ctx.verify_certificate = &t->verifier->super;
	} // else: picotls accepts any server certificate
	if (ngtcp2_crypto_picotls_configure_client_context(&t->ctx) != 0) {
		goto fail;
	}

	ngtcp2_crypto_picotls_ctx_init(&t->cptls);
	if (!(t->cptls.ptls = ptls_client_new(&t->ctx))) {
		goto fail;
	}
	*ptls_get_data_ptr(t->cptls.ptls) = conn_ref;

	ptls_handshake_properties_t *props = &t->cptls.handshake_properties;
	// Room for the QUIC transport parameters, filled in by ngtcp2_crypto_picotls_configure_client_session().
	t->extensions[0].type = UINT16_MAX;
	t->extensions[1].type = UINT16_MAX;
	props->additional_extensions = t->extensions;
	memcpy(t->alpn_buf, config->alpn, alpn_len);
	t->alpn = ptls_iovec_init(t->alpn_buf, alpn_len);
	props->client.negotiated_protocols.list = &t->alpn;
	props->client.negotiated_protocols.count = 1;
	if (config->server_name && ptls_set_server_name(t->cptls.ptls, config->server_name, 0) != 0) {
		goto fail;
	}
	*tls = t;
	return 0;

fail:
	scion_quic_tls_free(t);
	return SCION_ERR_TLS_SETUP_FAIL;
}

int scion_quic_tls_attach(struct scion_quic_tls *tls, ngtcp2_conn *conn)
{
	if (ngtcp2_crypto_picotls_configure_client_session(&tls->cptls, conn) != 0) {
		return SCION_ERR_TLS_SETUP_FAIL;
	}
	ngtcp2_conn_set_tls_native_handle(conn, &tls->cptls);
	return 0;
}

void scion_quic_tls_free(struct scion_quic_tls *tls)
{
	if (!tls) {
		return;
	}
	ngtcp2_crypto_picotls_deconfigure_session(&tls->cptls);
	if (tls->cptls.ptls) {
		ptls_free(tls->cptls.ptls);
	}
	if (tls->verifier) {
		mbedtls_x509_crt_free(&tls->verifier->ca);
		free(tls->verifier);
	}
	free(tls);
}

int scion_quic_tls_random(uint8_t *buf, size_t len)
{
	return psa_generate_random(buf, len) == PSA_SUCCESS ? 0 : -1;
}
