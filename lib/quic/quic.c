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

// QUIC client over SCION: ngtcp2 on top of a connected SCION UDP socket, with one bidirectional stream. The TLS
// library is hidden behind tls.h.

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <time.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include "scion/scion.h"
#include "scion/scion_quic.h"

#include "tls.h"

// QUIC payload that fits any SCION path: the SCION and UDP headers take ~100 bytes of a 1280+ byte MTU.
#define MAX_UDP_PAYLOAD 1200
#define SCID_LEN 8
#define IDLE_TIMEOUT (300 * NGTCP2_SECONDS)
// Flow control windows. Small, as embedded devices have little RAM; the receive buffer never exceeds STREAM_WINDOW.
#define STREAM_WINDOW (64 * 1024)
#define CONN_WINDOW (128 * 1024)

struct scion_quic_conn {
	struct scion_socket *socket;
	int fd;
	struct sockaddr_storage local, remote;
	socklen_t local_len, remote_len;

	ngtcp2_crypto_conn_ref conn_ref;
	ngtcp2_conn *conn;
	struct scion_quic_tls *tls;
	ngtcp2_ccerr last_error;

	int64_t stream_id; // -1 until the handshake is done
	uint8_t *tx;
	size_t tx_len, tx_off, tx_cap;
	bool fin_requested, fin_sent;
	uint8_t *rx;
	size_t rx_len, rx_cap;
	bool peer_fin;

	bool debug;
	bool established;
	bool closed;
	int error; // why the connection closed
};

static uint64_t now_ns(void)
{
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static void log_printf(void *user_data, const char *fmt, ...)
{
	va_list ap;
	(void)user_data;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static void send_packet(struct scion_quic_conn *c, const uint8_t *data, size_t len)
{
	struct iovec iov = { .iov_base = (void *)data, .iov_len = len };
	struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1 };
	// A lost packet is recovered by QUIC, errors are not fatal here.
	(void)scion_sendmsg(c->socket, &msg, 0, 0, NULL);
}

static void mark_closed(struct scion_quic_conn *c, int error)
{
	if (!c->closed) {
		c->closed = true;
		c->error = c->established ? error : SCION_ERR_QUIC_HANDSHAKE_FAIL;
	}
}

static void write_close_packet(struct scion_quic_conn *c)
{
	uint8_t buf[MAX_UDP_PAYLOAD];
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info pi;

	if (ngtcp2_conn_in_closing_period(c->conn) || ngtcp2_conn_in_draining_period(c->conn)) {
		return;
	}
	ngtcp2_path_storage_zero(&ps);
	ngtcp2_ssize n = ngtcp2_conn_write_connection_close(
		c->conn, &ps.path, &pi, buf, sizeof(buf), &c->last_error, now_ns());
	if (n > 0) {
		send_packet(c, buf, (size_t)n);
	}
}

static void fail(struct scion_quic_conn *c, int liberr)
{
	if (c->closed) {
		return;
	}
	if (!c->last_error.error_code && c->last_error.type == NGTCP2_CCERR_TYPE_TRANSPORT) {
		if (liberr == NGTCP2_ERR_CRYPTO) {
			ngtcp2_ccerr_set_tls_alert(&c->last_error, ngtcp2_conn_get_tls_alert(c->conn), NULL, 0);
		} else {
			ngtcp2_ccerr_set_liberr(&c->last_error, liberr, NULL, 0);
		}
	}
	if (liberr != NGTCP2_ERR_DRAINING && liberr != NGTCP2_ERR_IDLE_CLOSE && liberr != NGTCP2_ERR_CLOSING) {
		write_close_packet(c);
	}
	mark_closed(c, SCION_ERR_QUIC_CLOSED);
}

// Hands the queued stream data (and the FIN) to ngtcp2 and sends the resulting packets.
static void flush(struct scion_quic_conn *c)
{
	uint8_t buf[MAX_UDP_PAYLOAD];
	ngtcp2_path_storage ps;
	ngtcp2_pkt_info pi;
	bool stream_blocked = false;

	if (c->closed) {
		return;
	}
	ngtcp2_path_storage_zero(&ps);

	for (;;) {
		ngtcp2_vec datav = { 0 };
		size_t datavcnt = 0;
		int64_t stream_id = -1;
		uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_NONE;
		ngtcp2_ssize wdatalen = -1;

		if (!stream_blocked && c->stream_id >= 0) {
			if (c->tx_len > c->tx_off) {
				stream_id = c->stream_id;
				datav.base = c->tx + c->tx_off;
				datav.len = c->tx_len - c->tx_off;
				datavcnt = 1;
			}
			if (c->fin_requested && !c->fin_sent) {
				stream_id = c->stream_id;
				flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
			}
		}

		ngtcp2_ssize n = ngtcp2_conn_writev_stream(
			c->conn, &ps.path, &pi, buf, sizeof(buf), &wdatalen, flags, stream_id, &datav, datavcnt, now_ns());
		if (n < 0) {
			if (n == NGTCP2_ERR_STREAM_DATA_BLOCKED || n == NGTCP2_ERR_STREAM_SHUT_WR) {
				stream_blocked = true;
				continue;
			}
			fail(c, (int)n);
			return;
		}
		if (wdatalen >= 0) {
			c->tx_off += (size_t)wdatalen;
			if ((flags & NGTCP2_WRITE_STREAM_FLAG_FIN) && c->tx_off == c->tx_len) {
				c->fin_sent = true;
			}
		}
		if (c->tx_off == c->tx_len) {
			c->tx_off = c->tx_len = 0;
		}
		if (n == 0) {
			return;
		}
		send_packet(c, buf, (size_t)n);
	}
}

static void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
	(void)rand_ctx;
	scion_quic_tls_random(dest, destlen);
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data)
{
	(void)conn;
	(void)user_data;
	if (scion_quic_tls_random(cid->data, cidlen) != 0
		|| scion_quic_tls_random(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	cid->datalen = cidlen;
	return 0;
}

static int handshake_completed_cb(ngtcp2_conn *conn, void *user_data)
{
	struct scion_quic_conn *c = user_data;
	if (ngtcp2_conn_open_bidi_stream(conn, &c->stream_id, NULL) != 0) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}
	c->established = true;
	return 0;
}

static int recv_stream_data_cb(ngtcp2_conn *conn, uint32_t flags, int64_t stream_id, uint64_t offset,
	const uint8_t *data, size_t datalen, void *user_data, void *stream_user_data)
{
	struct scion_quic_conn *c = user_data;
	(void)conn;
	(void)offset;
	(void)stream_user_data;

	if (stream_id != c->stream_id) {
		return 0;
	}
	if (flags & NGTCP2_STREAM_DATA_FLAG_FIN) {
		c->peer_fin = true;
	}
	if (datalen == 0) { // only the FIN
		return 0;
	}
	if (c->rx_len + datalen > c->rx_cap) {
		// Bounded by the stream window: the window is only extended when the application reads.
		size_t cap = c->rx_cap ? c->rx_cap : 4096;
		while (cap < c->rx_len + datalen) {
			cap *= 2;
		}
		uint8_t *rx = realloc(c->rx, cap);
		if (!rx) {
			return NGTCP2_ERR_CALLBACK_FAILURE;
		}
		c->rx = rx;
		c->rx_cap = cap;
	}
	memcpy(c->rx + c->rx_len, data, datalen);
	c->rx_len += datalen;
	return 0;
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	return ((struct scion_quic_conn *)conn_ref->user_data)->conn;
}

static int open_socket(struct scion_quic_conn *c, struct scion_network *network, const struct sockaddr *addr,
	socklen_t addrlen, scion_ia ia, const struct scion_quic_config *config)
{
	int ret = scion_socket(
		&c->socket, scion_network_get_local_addr_family(network), SCION_SOCK_DGRAM, SCION_PROTO_UDP, network);
	if (ret != 0) {
		return ret;
	}
	if (config->policy && (ret = scion_setsockpolicy(c->socket, config->policy)) != 0) {
		return ret;
	}
	if (config->local_addr && (ret = scion_bind(c->socket, config->local_addr, config->local_addrlen)) != 0) {
		return ret;
	}
	if ((ret = scion_connect(c->socket, addr, addrlen, ia)) != 0) {
		return ret;
	}
	memcpy(&c->remote, addr, addrlen);
	c->remote_len = addrlen;
	c->local_len = sizeof(c->local);
	if ((ret = scion_getsockname(c->socket, (struct sockaddr *)&c->local, &c->local_len, NULL)) != 0) {
		return ret;
	}
	return scion_getsockfd(c->socket, &c->fd);
}

int scion_quic_connect(struct scion_quic_conn **conn, struct scion_network *network, const struct sockaddr *addr,
	socklen_t addrlen, scion_ia ia, const struct scion_quic_config *config)
{
	if (!conn || !network || !addr || addrlen > sizeof(struct sockaddr_storage) || !config || !config->alpn) {
		return SCION_ERR_GENERIC;
	}
	struct scion_quic_conn *c = calloc(1, sizeof(*c));
	if (!c) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}
	c->stream_id = -1;
	c->debug = config->debug;
	ngtcp2_ccerr_default(&c->last_error);
	c->conn_ref.get_conn = get_conn;
	c->conn_ref.user_data = c;

	int ret = open_socket(c, network, addr, addrlen, ia, config);
	if (ret != 0) {
		goto fail;
	}
	if ((ret = scion_quic_tls_new(&c->tls, config, &c->conn_ref)) != 0) {
		goto fail;
	}

	ngtcp2_path path = {
		.local = { .addr = (struct sockaddr *)&c->local, .addrlen = c->local_len },
		.remote = { .addr = (struct sockaddr *)&c->remote, .addrlen = c->remote_len },
	};
	ngtcp2_callbacks callbacks = {
		.client_initial = ngtcp2_crypto_client_initial_cb,
		.recv_retry = ngtcp2_crypto_recv_retry_cb,
		.version_negotiation = ngtcp2_crypto_version_negotiation_cb,
		.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
		.encrypt = ngtcp2_crypto_encrypt_cb,
		.decrypt = ngtcp2_crypto_decrypt_cb,
		.hp_mask = ngtcp2_crypto_hp_mask_cb,
		.update_key = ngtcp2_crypto_update_key_cb,
		.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
		.rand = rand_cb,
		.get_new_connection_id = get_new_connection_id_cb,
		.handshake_completed = handshake_completed_cb,
		.recv_stream_data = recv_stream_data_cb,
	};
	ngtcp2_settings settings;
	ngtcp2_settings_default(&settings);
	settings.initial_ts = now_ns();
	settings.max_tx_udp_payload_size = MAX_UDP_PAYLOAD;
	settings.no_tx_udp_payload_size_shaping = 1;
	if (config->debug) {
		settings.log_printf = log_printf;
	}
	ngtcp2_transport_params params;
	ngtcp2_transport_params_default(&params);
	params.initial_max_streams_bidi = 0; // the server does not open streams
	params.initial_max_streams_uni = 0;
	params.initial_max_stream_data_bidi_local = STREAM_WINDOW;
	params.initial_max_data = CONN_WINDOW;
	params.max_idle_timeout = IDLE_TIMEOUT;
	params.max_udp_payload_size = MAX_UDP_PAYLOAD;

	ngtcp2_cid dcid = { .datalen = NGTCP2_MIN_INITIAL_DCIDLEN }, scid = { .datalen = SCID_LEN };
	if (scion_quic_tls_random(dcid.data, dcid.datalen) != 0 || scion_quic_tls_random(scid.data, scid.datalen) != 0) {
		ret = SCION_ERR_TLS_SETUP_FAIL;
		goto fail;
	}
	if (ngtcp2_conn_client_new(
			&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, NULL, c)
		!= 0) {
		ret = SCION_ERR_MEM_ALLOC_FAIL;
		goto fail;
	}
	if ((ret = scion_quic_tls_attach(c->tls, c->conn)) != 0) {
		goto fail;
	}

	flush(c); // sends the Initial packet
	if (c->closed) {
		ret = c->error;
		goto fail;
	}
	*conn = c;
	return 0;

fail:
	c->closed = true; // nothing to tell the server
	scion_quic_close(c);
	return ret;
}

int scion_quic_getfd(const struct scion_quic_conn *conn, int *fd)
{
	*fd = conn->fd;
	return 0;
}

int scion_quic_timeout(const struct scion_quic_conn *conn)
{
	if (conn->closed) {
		return 0;
	}
	ngtcp2_tstamp expiry = ngtcp2_conn_get_expiry(conn->conn);
	if (expiry == UINT64_MAX) {
		return -1;
	}
	ngtcp2_tstamp now = now_ns();
	if (expiry <= now) {
		return 0;
	}
	uint64_t ms = (expiry - now + 999999) / 1000000;
	return ms > INT32_MAX ? INT32_MAX : (int)ms;
}

int scion_quic_process(struct scion_quic_conn *conn)
{
	struct scion_quic_conn *c = conn;
	uint8_t buf[2048];

	if (c->closed) {
		return c->error;
	}
	for (;;) {
		struct sockaddr_storage from;
		struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
		struct msghdr msg = { .msg_name = &from, .msg_namelen = sizeof(from), .msg_iov = &iov, .msg_iovlen = 1 };
		ssize_t n = scion_recvmsg(c->socket, &msg, MSG_DONTWAIT, NULL, NULL);
		if (n < 0) {
			break; // SCION_ERR_WOULD_BLOCK, or a packet csnet could not decode
		}
		ngtcp2_path path = {
			.local = { .addr = (struct sockaddr *)&c->local, .addrlen = c->local_len },
			.remote = { .addr = (struct sockaddr *)&c->remote, .addrlen = c->remote_len },
		};
		ngtcp2_pkt_info pi = { 0 };
		int rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, buf, (size_t)n, now_ns());
		if (rv != 0) {
			if (c->debug && rv != NGTCP2_ERR_DRAINING) {
				fprintf(stderr, "scion_quic: %s\n", ngtcp2_strerror(rv));
			}
			fail(c, rv);
			return c->error;
		}
	}
	if (ngtcp2_conn_get_expiry(c->conn) <= now_ns()) {
		int rv = ngtcp2_conn_handle_expiry(c->conn, now_ns());
		if (rv != 0) {
			fail(c, rv);
			return c->error;
		}
	}
	flush(c);
	return c->closed ? c->error : 0;
}

int scion_quic_wait(struct scion_quic_conn *conn, int timeout_ms)
{
	if (conn->closed) {
		return conn->error;
	}
	int wait = scion_quic_timeout(conn);
	if (wait < 0 || (timeout_ms >= 0 && timeout_ms < wait)) {
		wait = timeout_ms;
	}
	fd_set rfds;
	FD_ZERO(&rfds);
	FD_SET(conn->fd, &rfds);
	struct timeval tv = { .tv_sec = wait / 1000, .tv_usec = (wait % 1000) * 1000 };
	(void)select(conn->fd + 1, &rfds, NULL, NULL, wait < 0 ? NULL : &tv);
	return scion_quic_process(conn);
}

bool scion_quic_is_established(const struct scion_quic_conn *conn)
{
	return conn->established && !conn->closed;
}

ssize_t scion_quic_write(struct scion_quic_conn *conn, const void *buf, size_t len)
{
	struct scion_quic_conn *c = conn;

	if (c->closed) {
		return c->error;
	}
	if (c->fin_requested) {
		return SCION_ERR_GENERIC;
	}
	if (c->tx_len + len > c->tx_cap) {
		size_t cap = c->tx_cap ? c->tx_cap : 1024;
		while (cap < c->tx_len + len) {
			cap *= 2;
		}
		uint8_t *tx = realloc(c->tx, cap);
		if (!tx) {
			return SCION_ERR_MEM_ALLOC_FAIL;
		}
		c->tx = tx;
		c->tx_cap = cap;
	}
	memcpy(c->tx + c->tx_len, buf, len);
	c->tx_len += len;
	flush(c);
	return c->closed ? c->error : (ssize_t)len;
}

int scion_quic_shutdown(struct scion_quic_conn *conn)
{
	if (conn->closed) {
		return conn->error;
	}
	conn->fin_requested = true;
	flush(conn);
	return conn->closed ? conn->error : 0;
}

ssize_t scion_quic_read(struct scion_quic_conn *conn, void *buf, size_t len)
{
	struct scion_quic_conn *c = conn;

	if (c->rx_len == 0) {
		if (c->peer_fin) {
			return 0;
		}
		return c->closed ? c->error : SCION_ERR_WOULD_BLOCK;
	}
	size_t n = len < c->rx_len ? len : c->rx_len;
	memcpy(buf, c->rx, n);
	memmove(c->rx, c->rx + n, c->rx_len - n);
	c->rx_len -= n;
	if (!c->closed) {
		// The data left the buffer: let the server send more.
		ngtcp2_conn_extend_max_stream_offset(c->conn, c->stream_id, n);
		ngtcp2_conn_extend_max_offset(c->conn, n);
		flush(c);
	}
	return (ssize_t)n;
}

void scion_quic_close(struct scion_quic_conn *conn)
{
	struct scion_quic_conn *c = conn;

	if (!c) {
		return;
	}
	if (!c->closed && c->conn) {
		flush(c);
		ngtcp2_ccerr_set_application_error(&c->last_error, 0, NULL, 0);
		write_close_packet(c);
	}
	if (c->conn) {
		ngtcp2_conn_del(c->conn);
	}
	scion_quic_tls_free(c->tls);
	if (c->socket) {
		scion_close(c->socket);
	}
	free(c->tx);
	free(c->rx);
	free(c);
}
