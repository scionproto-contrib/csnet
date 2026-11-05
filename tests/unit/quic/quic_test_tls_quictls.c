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

// TLS of the test server with quictls.

#include <string.h>

#include <ngtcp2/ngtcp2_crypto_quictls.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "quic_test_server.h"

struct quic_test_tls {
	SSL_CTX *ctx;
};

static int select_alpn(
	SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
	(void)ssl;
	(void)arg;
	for (unsigned int i = 0; i + 1 <= inlen; i += 1u + in[i]) {
		if (in[i] == strlen(QUIC_TEST_ALPN) && i + 1u + in[i] <= inlen
			&& memcmp(in + i + 1, QUIC_TEST_ALPN, in[i]) == 0) {
			*out = in + i + 1;
			*outlen = in[i];
			return SSL_TLSEXT_ERR_OK;
		}
	}
	return SSL_TLSEXT_ERR_ALERT_FATAL;
}

struct quic_test_tls *quic_test_tls_new(void)
{
	struct quic_test_tls *tls = calloc(1, sizeof(*tls));
	if (!tls || !(tls->ctx = SSL_CTX_new(TLS_server_method()))
		|| ngtcp2_crypto_quictls_configure_server_context(tls->ctx) != 0
		|| SSL_CTX_use_certificate_chain_file(tls->ctx, QUIC_TEST_DATA_DIR "/server.pem") != 1
		|| SSL_CTX_use_PrivateKey_file(tls->ctx, QUIC_TEST_DATA_DIR "/server.key", SSL_FILETYPE_PEM) != 1) {
		quic_test_tls_free(tls);
		return NULL;
	}
	SSL_CTX_set_alpn_select_cb(tls->ctx, select_alpn, NULL);
	return tls;
}

void quic_test_tls_free(struct quic_test_tls *tls)
{
	if (tls) {
		SSL_CTX_free(tls->ctx);
		free(tls);
	}
}

void *quic_test_tls_session_new(struct quic_test_tls *tls, ngtcp2_crypto_conn_ref *conn_ref, void **native_handle)
{
	SSL *ssl = SSL_new(tls->ctx);
	if (ssl) {
		SSL_set_app_data(ssl, conn_ref);
		SSL_set_accept_state(ssl);
	}
	*native_handle = ssl;
	return ssl;
}

int quic_test_tls_session_attach(void *session, ngtcp2_conn *conn)
{
	(void)session;
	(void)conn;
	return 0;
}

void quic_test_tls_session_free(void *session)
{
	SSL_free(session);
}

void quic_test_tls_random(uint8_t *buf, size_t len)
{
	RAND_bytes(buf, (int)len);
}
