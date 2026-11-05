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

// A minimal QUIC server for the tests of scion_quic: one connection, one stream, on a SCION socket in the local AS
// (loopback), running in its own thread. It uses the same TLS library as scion_quic (quic_test_tls_*.c).

#pragma once

#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include "scion/scion.h"

#define QUIC_TEST_ALPN "test"
#define QUIC_TEST_SERVER_NAME "quic.test"
#define QUIC_TEST_CLOSE_ERROR 42

enum quic_test_mode {
	// When the client finished its stream: answers "echo: <data>" and finishes the stream.
	QUIC_TEST_ECHO,
	// When the client finished its stream: sends bulk_len bytes (byte i is i % 251) and finishes the stream.
	QUIC_TEST_BULK,
	// Closes the connection with application error QUIC_TEST_CLOSE_ERROR once the handshake is done.
	QUIC_TEST_CLOSE,
	// When the client finished its stream: finishes the stream without sending data.
	QUIC_TEST_EMPTY,
};

struct quic_test_server {
	// configuration, set before quic_test_server_start()
	enum quic_test_mode mode;
	size_t bulk_len;
	size_t stream_window; // flow control window of the stream the client sends on (default 256 KB)

	// state of the server thread
	struct scion_socket *socket;
	struct sockaddr_in addr; // where the server listens (loopback, ephemeral port)
	pthread_t thread;
	volatile bool stop;
	struct quic_test_tls *tls;
	void *tls_session;
	ngtcp2_crypto_conn_ref conn_ref;
	ngtcp2_conn *conn;
	struct sockaddr_storage local, remote;
	socklen_t local_len, remote_len;
	scion_ia remote_ia;
	int64_t stream_id;
	uint8_t *tx;
	size_t tx_len, tx_off;
	bool tx_fin, fin_sent, closed;

	// results, read after quic_test_server_stop()
	bool handshake_done;
	uint8_t *received;
	size_t received_len;
	bool received_fin;
};

// Opens the server socket in the network of the test fixture and starts the server thread.
void quic_test_server_start(struct quic_test_server *server, struct scion_network *network);
// Stops the thread and frees everything but the results (freed by quic_test_server_free()).
void quic_test_server_stop(struct quic_test_server *server);
void quic_test_server_free(struct quic_test_server *server);

// TLS of the server (quic_test_tls_quictls.c or quic_test_tls_picotls.c): certificate server.pem/server.key of
// testdata, ALPN QUIC_TEST_ALPN.
struct quic_test_tls *quic_test_tls_new(void);
void quic_test_tls_free(struct quic_test_tls *tls);
// Creates the TLS session of a connection and returns the handle for ngtcp2_conn_set_tls_native_handle().
void *quic_test_tls_session_new(struct quic_test_tls *tls, ngtcp2_crypto_conn_ref *conn_ref, void **native_handle);
// Called once the ngtcp2 connection exists (picotls needs it).
int quic_test_tls_session_attach(void *session, ngtcp2_conn *conn);
void quic_test_tls_session_free(void *session);
void quic_test_tls_random(uint8_t *buf, size_t len);

// Reads a file of testdata, NUL terminated. Returns NULL on error.
char *quic_test_read_file(const char *name, size_t *len);
