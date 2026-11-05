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

#include <arpa/inet.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cmocka.h>

#include "quic_test_server.h"

#define MAX_UDP_PAYLOAD 1200

static uint64_t now_ns(void)
{
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

char *quic_test_read_file(const char *name, size_t *len)
{
	char path[512];
	snprintf(path, sizeof(path), "%s/%s", QUIC_TEST_DATA_DIR, name);
	FILE *f = fopen(path, "rb");
	char *buf = NULL;
	long size;

	if (!f) {
		return NULL;
	}
	if (fseek(f, 0, SEEK_END) == 0 && (size = ftell(f)) >= 0 && fseek(f, 0, SEEK_SET) == 0
		&& (buf = malloc((size_t)size + 1)) != NULL) {
		*len = fread(buf, 1, (size_t)size, f);
		buf[*len] = '\0';
	}
	fclose(f);
	return buf;
}

static void send_packet(struct quic_test_server *s, const uint8_t *data, size_t len)
{
	(void)scion_sendto(s->socket, data, len, 0, (struct sockaddr *)&s->remote, s->remote_len, s->remote_ia, NULL);
}

static void queue(struct quic_test_server *s, const void *data, size_t len)
{
	uint8_t *tx = realloc(s->tx, s->tx_len + len);
	assert_non_null(tx);
	s->tx = tx;
	memcpy(s->tx + s->tx_len, data, len);
	s->tx_len += len;
}

static void write_packets(struct quic_test_server *s)
{
	uint8_t buf[MAX_UDP_PAYLOAD];
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info pi;
	bool blocked = false;

	ngtcp2_path_storage_zero(&ps);
	while (!s->closed) {
		ngtcp2_vec datav = { .base = s->tx + s->tx_off, .len = s->tx_len - s->tx_off };
		int64_t stream_id = -1;
		uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
		ngtcp2_ssize wdatalen = -1;

		if (!blocked && s->stream_id >= 0 && (datav.len > 0 || (s->tx_fin && !s->fin_sent))) {
			stream_id = s->stream_id;
			if (s->tx_fin) {
				flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
			}
		}
		ngtcp2_ssize n = ngtcp2_conn_writev_stream(s->conn, &ps.path, &pi, buf, sizeof(buf), &wdatalen, flags,
			stream_id, &datav, stream_id >= 0 ? 1 : 0, now_ns());
		if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED) {
			blocked = true;
			continue;
		}
		if (n < 0) {
			s->closed = true;
			return;
		}
		if (wdatalen >= 0) {
			s->tx_off += (size_t)wdatalen;
			if ((flags & NGTCP2_WRITE_STREAM_FLAG_FIN) && s->tx_off == s->tx_len) {
				s->fin_sent = true;
			}
		}
		if (n == 0) {
			return;
		}
		send_packet(s, buf, (size_t)n);
	}
}

static void close_connection(struct quic_test_server *s)
{
	uint8_t buf[MAX_UDP_PAYLOAD];
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info pi;
	ngtcp2_ccerr ccerr;

	ngtcp2_ccerr_set_application_error(&ccerr, QUIC_TEST_CLOSE_ERROR, NULL, 0);
	ngtcp2_path_storage_zero(&ps);
	ngtcp2_ssize n = ngtcp2_conn_write_connection_close(s->conn, &ps.path, &pi, buf, sizeof(buf), &ccerr, now_ns());
	if (n > 0) {
		send_packet(s, buf, (size_t)n);
	}
	s->closed = true;
}

static void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;
	quic_test_tls_random(dest, destlen);
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data)
{
	(void)conn;
	(void)user_data;
	quic_test_tls_random(cid->data, cidlen);
	quic_test_tls_random(token, NGTCP2_STATELESS_RESET_TOKENLEN);
	cid->datalen = cidlen;
	return 0;
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
	(void)conn;
	((struct quic_test_server *)user_data)->handshake_done = true;
	return 0;
}

static int stream_open_cb(ngtcp2_conn *conn, int64_t stream_id, void *user_data)
{
	(void)conn;
	struct quic_test_server *s = user_data;
	if (s->stream_id < 0) {
		s->stream_id = stream_id;
	}
	return 0;
}

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset,
	const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data)
{
	struct quic_test_server *s = user_data;
	(void)offset;
	(void)stream_user_data;

	uint8_t *received = realloc(s->received, s->received_len + datalen + 1);
	if (!received) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	s->received = received;
	if (datalen > 0) {
		memcpy(s->received + s->received_len, data, datalen);
	}
	s->received_len += datalen;
	ngtcp2_conn_extend_max_stream_offset(conn, stream_id, datalen);
	ngtcp2_conn_extend_max_offset(conn, datalen);

	if ((flags & NGTCP2_STREAM_DATA_FLAG_FIN) && !s->received_fin) {
		s->received_fin = true;
		if (s->mode == QUIC_TEST_ECHO) {
			queue(s, "echo: ", 6);
			queue(s, s->received, s->received_len);
		} else if (s->mode == QUIC_TEST_BULK) {
			uint8_t *bulk = malloc(s->bulk_len);
			assert_non_null(bulk);
			for (size_t i = 0; i < s->bulk_len; i++) {
				bulk[i] = (uint8_t)(i % 251);
			}
			queue(s, bulk, s->bulk_len);
			free(bulk);
		} // QUIC_TEST_EMPTY: only the FIN
		s->tx_fin = true;
	}
	return 0;
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	return ((struct quic_test_server *)conn_ref->user_data)->conn;
}

static int accept_connection(struct quic_test_server *s, const uint8_t *pkt, size_t len)
{
	ngtcp2_pkt_hd hd;
	if (ngtcp2_accept(&hd, pkt, len) != 0) {
		return -1;
	}
	void *native_handle;
	s->tls_session = quic_test_tls_session_new(s->tls, &s->conn_ref, &native_handle);
	assert_non_null(s->tls_session);

	ngtcp2_path path = {
		.local = { .addr = (struct sockaddr *)&s->local, .addrlen = s->local_len },
		.remote = { .addr = (struct sockaddr *)&s->remote, .addrlen = s->remote_len },
	};
	ngtcp2_callbacks callbacks = {
		.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb,
		.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
		.encrypt = ngtcp2_crypto_encrypt_cb,
		.decrypt = ngtcp2_crypto_decrypt_cb,
		.hp_mask = ngtcp2_crypto_hp_mask_cb,
		.update_key = ngtcp2_crypto_update_key_cb,
		.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
		.version_negotiation = ngtcp2_crypto_version_negotiation_cb,
		.rand = rand_cb,
		.get_new_connection_id = get_new_connection_id_cb,
		.handshake_completed = handshake_completed_cb,
		.stream_open = stream_open_cb,
		.recv_stream_data = recv_stream_data_cb,
	};
	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = now_ns();
	settings.max_tx_udp_payload_size = MAX_UDP_PAYLOAD;
	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);
	params.initial_max_streams_bidi = 1;
	params.initial_max_stream_data_bidi_remote = s->stream_window ? s->stream_window : 256 * 1024;
	params.initial_max_data = 1024 * 1024;
	params.max_idle_timeout = 30 * NGTCP2_SECONDS;
	params.original_dcid = hd.dcid;
	params.original_dcid_present = 1;
	params.stateless_reset_token_present = 1;
	quic_test_tls_random(params.stateless_reset_token, sizeof(params.stateless_reset_token));
	ngtcp2_cid scid = { .datalen = 8 };
	quic_test_tls_random(scid.data, scid.datalen);

	assert_int_equal(
		ngtcp2_conn_server_new(&s->conn, &hd.scid, &scid, &path, hd.version, &callbacks, &settings, &params, NULL, s),
		0);
	assert_int_equal(quic_test_tls_session_attach(s->tls_session, s->conn), 0);
	ngtcp2_conn_set_tls_native_handle(s->conn, native_handle);
	return 0;
}

static void *server_thread(void *arg)
{
	struct quic_test_server *s = arg;
	int fd;
	assert_int_equal(scion_getsockfd(s->socket, &fd), 0);

	while (!s->stop) {
		int timeout = 10;
		if (s->conn && !s->closed) {
			ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(s->conn), now = now_ns();
			if (expiry <= now) {
				timeout = 0;
			} else if ((expiry - now) / 1000000 < (uint64_t)timeout) {
				timeout = (int)((expiry - now) / 1000000);
			}
		}
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		(void)poll(&pfd, 1, timeout);

		for (;;) {
			uint8_t buf[2048];
			struct sockaddr_storage from;
			socklen_t from_len = sizeof(from);
			scion_ia ia;
			ssize_t n = scion_recvfrom(
				s->socket, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&from, &from_len, &ia, NULL);
			if (n <= 0) {
				break;
			}
			if (s->closed) {
				continue;
			}
			if (!s->conn) {
				memcpy(&s->remote, &from, from_len);
				s->remote_len = from_len;
				s->remote_ia = ia;
				if (accept_connection(s, buf, (size_t)n) != 0) {
					continue;
				}
			}
			ngtcp2_path path = {
				.local = { .addr = (struct sockaddr *)&s->local, .addrlen = s->local_len },
				.remote = { .addr = (struct sockaddr *)&s->remote, .addrlen = s->remote_len },
			};
			ngtcp2_pkt_info pi = { 0 };
			if (ngtcp2_conn_read_pkt(s->conn, &path, &pi, buf, (size_t)n, now_ns()) != 0) {
				close_connection(s); // also covers a failed handshake: sends the TLS alert
			}
		}
		if (!s->conn || s->closed) {
			continue;
		}
		if (ngtcp2_conn_get_expiry(s->conn) <= now_ns() && ngtcp2_conn_handle_expiry(s->conn, now_ns()) != 0) {
			s->closed = true;
			continue;
		}
		if (s->mode == QUIC_TEST_CLOSE && s->handshake_done) {
			write_packets(s); // deliver HANDSHAKE_DONE first
			close_connection(s);
			continue;
		}
		write_packets(s);
	}
	return NULL;
}

void quic_test_server_start(struct quic_test_server *s, struct scion_network *network)
{
	s->stream_id = -1;
	s->conn_ref.get_conn = get_conn;
	s->conn_ref.user_data = s;
	s->tls = quic_test_tls_new();
	assert_non_null(s->tls);

	assert_int_equal(scion_socket(&s->socket, SCION_AF_INET, SCION_SOCK_DGRAM, SCION_PROTO_UDP, network), 0);
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK) };
	assert_int_equal(scion_bind(s->socket, (struct sockaddr *)&addr, sizeof(addr)), 0);
	socklen_t len = sizeof(s->addr);
	assert_int_equal(scion_getsockname(s->socket, (struct sockaddr *)&s->addr, &len, NULL), 0);
	memcpy(&s->local, &s->addr, sizeof(s->addr));
	s->local_len = sizeof(s->addr);

	assert_int_equal(pthread_create(&s->thread, NULL, server_thread, s), 0);
}

void quic_test_server_stop(struct quic_test_server *s)
{
	s->stop = true;
	pthread_join(s->thread, NULL);
	if (s->conn) {
		ngtcp2_conn_del(s->conn);
		s->conn = NULL;
	}
	if (s->tls_session) {
		quic_test_tls_session_free(s->tls_session);
		s->tls_session = NULL;
	}
	quic_test_tls_free(s->tls);
	s->tls = NULL;
	scion_close(s->socket);
	s->socket = NULL;
	free(s->tx);
	s->tx = NULL;
}

void quic_test_server_free(struct quic_test_server *s)
{
	free(s->received);
	s->received = NULL;
}
