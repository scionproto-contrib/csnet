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

// TLS backend: quictls (OpenSSL 1.1.1 with the QUIC API).

#include <stdlib.h>
#include <string.h>

#include <ngtcp2/ngtcp2_crypto_quictls.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>

#include "tls.h"

struct scion_quic_tls {
	SSL_CTX *ctx;
	SSL *ssl;
};

static int load_ca(SSL_CTX *ctx, const char *pem, size_t len)
{
	BIO *bio = BIO_new_mem_buf(pem, (int)len);
	X509_STORE *store = SSL_CTX_get_cert_store(ctx);
	X509 *cert;
	int count = 0;

	if (!bio) {
		return -1;
	}
	while ((cert = PEM_read_bio_X509(bio, NULL, NULL, NULL)) != NULL) {
		if (X509_STORE_add_cert(store, cert) == 1) {
			count++;
		}
		X509_free(cert);
	}
	ERR_clear_error(); // end of the PEM data
	BIO_free(bio);
	return count > 0 ? 0 : -1;
}

int scion_quic_tls_new(
	struct scion_quic_tls **tls, const struct scion_quic_config *config, ngtcp2_crypto_conn_ref *conn_ref)
{
	struct scion_quic_tls *t = calloc(1, sizeof(*t));
	size_t alpn_len = strlen(config->alpn);
	unsigned char alpn[256];

	if (!t) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}
	if (alpn_len == 0 || alpn_len > 255) {
		goto fail;
	}
	t->ctx = SSL_CTX_new(TLS_client_method());
	if (!t->ctx || ngtcp2_crypto_quictls_configure_client_context(t->ctx) != 0) {
		goto fail;
	}
	if (config->ca_pem) {
		if (load_ca(t->ctx, config->ca_pem, config->ca_pem_len) != 0) {
			goto fail;
		}
		SSL_CTX_set_verify(t->ctx, SSL_VERIFY_PEER, NULL);
	} else {
		SSL_CTX_set_verify(t->ctx, SSL_VERIFY_NONE, NULL);
	}

	t->ssl = SSL_new(t->ctx);
	if (!t->ssl) {
		goto fail;
	}
	SSL_set_app_data(t->ssl, conn_ref);
	SSL_set_connect_state(t->ssl);
	alpn[0] = (unsigned char)alpn_len;
	memcpy(alpn + 1, config->alpn, alpn_len);
	if (SSL_set_alpn_protos(t->ssl, alpn, (unsigned int)alpn_len + 1) != 0) {
		goto fail;
	}
	if (config->server_name) {
		SSL_set_tlsext_host_name(t->ssl, config->server_name);
		if (config->ca_pem && SSL_set1_host(t->ssl, config->server_name) != 1) {
			goto fail;
		}
	}
	*tls = t;
	return 0;

fail:
	scion_quic_tls_free(t);
	return SCION_ERR_TLS_SETUP_FAIL;
}

int scion_quic_tls_attach(struct scion_quic_tls *tls, ngtcp2_conn *conn)
{
	ngtcp2_conn_set_tls_native_handle(conn, tls->ssl);
	return 0;
}

void scion_quic_tls_free(struct scion_quic_tls *tls)
{
	if (!tls) {
		return;
	}
	SSL_free(tls->ssl);
	SSL_CTX_free(tls->ctx);
	free(tls);
}

int scion_quic_tls_random(uint8_t *buf, size_t len)
{
	return RAND_bytes(buf, (int)len) == 1 ? 0 : -1;
}
