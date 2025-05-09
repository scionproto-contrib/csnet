/*
 * ngtcp2
 *
 * Copyright (c) 2021 ngtcp2 contributors
 * see https://github.com/ngtcp2/ngtcp2/blob/90b97f121051a087e742d95c1980788255b84c09/examples/simpleclient.c
 *
 * Copyright (c) 2025 ETH Zurich
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif /* defined(HAVE_CONFIG_H) */

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_quictls.h>

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <ev.h>

#include <scion/scion.h>

#define REMOTE_AS "2-ff00:0:222"
#define REMOTE_HOST "fd00:f00d:cafe::7f00:55"
#define REMOTE_PORT 31003
#define REMOTE_AF SCION_AF_IPV6
#define ALPN "\xahello-quic"
#define MESSAGE "Hello QUIC"
#define SCION_TOPO_PATH "../topology/topology.json"

static uint64_t timestamp(void)
{
	struct timespec tp;

	if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
		fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return (uint64_t)tp.tv_sec * NGTCP2_SECONDS + (uint64_t)tp.tv_nsec;
}

static int create_network(const char *topology_path, struct scion_network **network, struct scion_topology **topology)
{
	int ret = scion_topology_from_file(topology, topology_path);
	if (ret != 0) {
		return ret;
	}

	ret = scion_network(network, *topology);
	if (ret != 0) {
		goto cleanup_topology;
	}

	return 0;

cleanup_topology:
	scion_topology_free(*topology);

	return ret;
}

static int create_sock(struct sockaddr *addr, socklen_t *paddrlen, struct scion_socket **socket, const char *host,
	uint16_t port, struct scion_network *network)
{
	if (REMOTE_AF == SCION_AF_IPV4) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		addr_in->sin_family = AF_INET;
		addr_in->sin_port = htons(port);
		inet_pton(AF_INET, host, &addr_in->sin_addr);
		*paddrlen = sizeof(struct sockaddr_in);
	} else {
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
		addr_in6->sin6_family = AF_INET6;
		addr_in6->sin6_port = htons(port);
		inet_pton(AF_INET6, host, &addr_in6->sin6_addr);
		*paddrlen = sizeof(struct sockaddr_in6);
	}

	return scion_socket(socket, SCION_AF_IPV4, SCION_PROTO_UDP, network);
}

static int connect_sock(struct sockaddr *local_addr, socklen_t *plocal_addrlen, struct scion_socket *socket,
	const struct sockaddr *remote_addr, size_t remote_addrlen, const char *remote_ia)
{
	scion_ia ia;
	int ret = scion_ia_parse(remote_ia, strlen(remote_ia), &ia);
	if (ret != 0) {
		return ret;
	}

	ret = scion_connect(socket, remote_addr, remote_addrlen, ia);
	if (ret != 0) {
		return ret;
	}

	ret = scion_getsockname(socket, local_addr, plocal_addrlen, NULL);
	return ret;
}

struct client {
	ngtcp2_crypto_conn_ref conn_ref;
	struct scion_topology *topology;
	struct scion_network *network;
	struct scion_socket *socket;
	struct sockaddr_storage local_addr;
	socklen_t local_addrlen;
	SSL_CTX *ssl_ctx;
	SSL *ssl;
	ngtcp2_conn *conn;

	struct {
		int64_t stream_id;
		const uint8_t *data;
		size_t datalen;
		size_t nwrite;
	} stream;

	ngtcp2_ccerr last_error;

	ev_io rev;
	ev_timer timer;
};

static int numeric_host_family(const char *hostname, int family)
{
	uint8_t dst[sizeof(struct in6_addr)];
	return inet_pton(family, hostname, dst) == 1;
}

static int numeric_host(const char *hostname)
{
	return numeric_host_family(hostname, AF_INET) || numeric_host_family(hostname, AF_INET6);
}

static int client_ssl_init(struct client *c)
{
	c->ssl_ctx = SSL_CTX_new(TLS_client_method());
	if (!c->ssl_ctx) {
		fprintf(stderr, "SSL_CTX_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto error;
	}

	SSL_CTX_set_verify(c->ssl_ctx, SSL_VERIFY_NONE, NULL);

	if (ngtcp2_crypto_quictls_configure_client_context(c->ssl_ctx) != 0) {
		fprintf(stderr, "ngtcp2_crypto_quictls_configure_client_context failed\n");
		goto cleanup_ssl_ctx;
	}

	c->ssl = SSL_new(c->ssl_ctx);
	if (!c->ssl) {
		fprintf(stderr, "SSL_new: %s\n", ERR_error_string(ERR_get_error(), NULL));
		goto cleanup_ssl_ctx;
	}

	SSL_set_app_data(c->ssl, &c->conn_ref);
	SSL_set_connect_state(c->ssl);
	SSL_set_alpn_protos(c->ssl, (const unsigned char *)ALPN, sizeof(ALPN) - 1);
	if (!numeric_host(REMOTE_HOST)) {
		SSL_set_tlsext_host_name(c->ssl, REMOTE_HOST);
	}

	return 0;

cleanup_ssl_ctx:
	SSL_CTX_free(c->ssl_ctx);

error:
	return -1;
}

static void rand_cb(uint8_t *dest, size_t destlen, const ngtcp2_rand_ctx *rand_ctx)
{
	size_t i;
	(void)rand_ctx;

	for (i = 0; i < destlen; ++i) {
		*dest = (uint8_t)random();
	}
}

static int get_new_connection_id_cb(ngtcp2_conn *conn, ngtcp2_cid *cid, uint8_t *token, size_t cidlen, void *user_data)
{
	(void)conn;
	(void)user_data;

	if (RAND_bytes(cid->data, (int)cidlen) != 1) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	cid->datalen = cidlen;

	if (RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
		return NGTCP2_ERR_CALLBACK_FAILURE;
	}

	return 0;
}

static int extend_max_local_streams_bidi(ngtcp2_conn *conn, uint64_t max_streams, void *user_data)
{
#ifdef MESSAGE
	struct client *c = user_data;
	int rv;
	int64_t stream_id;
	(void)max_streams;

	if (c->stream.stream_id != -1) {
		return 0;
	}

	rv = ngtcp2_conn_open_bidi_stream(conn, &stream_id, NULL);
	if (rv != 0) {
		return 0;
	}

	c->stream.stream_id = stream_id;
	c->stream.data = (const uint8_t *)MESSAGE;
	c->stream.datalen = sizeof(MESSAGE) - 1;

	return 0;
#else /* !defined(MESSAGE) */
	(void)conn;
	(void)max_streams;
	(void)user_data;

	return 0;
#endif /* !defined(MESSAGE) */
}

static void log_printf(void *user_data, const char *fmt, ...)
{
	va_list ap;
	(void)user_data;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	fprintf(stderr, "\n");
}

static int client_quic_init(struct client *c, const struct sockaddr *remote_addr, socklen_t remote_addrlen,
	const struct sockaddr *local_addr, socklen_t local_addrlen)
{
	ngtcp2_path path = {
    .local =
      {
        .addr = (struct sockaddr *)local_addr,
        .addrlen = local_addrlen,
      },
    .remote =
      {
        .addr = (struct sockaddr *)remote_addr,
        .addrlen = remote_addrlen,
      },
  };
	ngtcp2_callbacks callbacks = {
		.client_initial = ngtcp2_crypto_client_initial_cb,
		.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb,
		.encrypt = ngtcp2_crypto_encrypt_cb,
		.decrypt = ngtcp2_crypto_decrypt_cb,
		.hp_mask = ngtcp2_crypto_hp_mask_cb,
		.recv_retry = ngtcp2_crypto_recv_retry_cb,
		.extend_max_local_streams_bidi = extend_max_local_streams_bidi,
		.rand = rand_cb,
		.get_new_connection_id = get_new_connection_id_cb,
		.update_key = ngtcp2_crypto_update_key_cb,
		.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb,
		.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb,
		.get_path_challenge_data = ngtcp2_crypto_get_path_challenge_data_cb,
		.version_negotiation = ngtcp2_crypto_version_negotiation_cb,
	};
	ngtcp2_cid dcid, scid;
	ngtcp2_settings settings;
	ngtcp2_transport_params params;
	int rv;

	dcid.datalen = NGTCP2_MIN_INITIAL_DCIDLEN;
	if (RAND_bytes(dcid.data, (int)dcid.datalen) != 1) {
		fprintf(stderr, "RAND_bytes failed\n");
		return -1;
	}

	scid.datalen = 8;
	if (RAND_bytes(scid.data, (int)scid.datalen) != 1) {
		fprintf(stderr, "RAND_bytes failed\n");
		return -1;
	}

	ngtcp2_settings_default(&settings);

	settings.initial_ts = timestamp();
	settings.log_printf = log_printf;

	ngtcp2_transport_params_default(&params);

	params.initial_max_streams_uni = 3;
	params.initial_max_stream_data_bidi_local = 128 * 1024;
	params.initial_max_data = 1024 * 1024;

	rv = ngtcp2_conn_client_new(
		&c->conn, &dcid, &scid, &path, NGTCP2_PROTO_VER_V1, &callbacks, &settings, &params, NULL, c);
	if (rv != 0) {
		fprintf(stderr, "ngtcp2_conn_client_new: %s\n", ngtcp2_strerror(rv));
		return -1;
	}

	ngtcp2_conn_set_tls_native_handle(c->conn, c->ssl);

	return 0;
}

static int client_read(struct client *c)
{
	uint8_t buf[65536];
	struct sockaddr_storage addr;
	socklen_t addrlen = sizeof(addr);

	ssize_t nread;
	ngtcp2_path path;
	ngtcp2_pkt_info pi = { 0 };
	int rv;

	for (;;) {
		nread = scion_recvfrom(
			c->socket, buf, sizeof(buf), MSG_DONTWAIT, (struct sockaddr *)&addr, &addrlen, NULL, NULL);

		if (nread < 0) {
			if (nread != SCION_WOULD_BLOCK) {
				fprintf(stderr, "recvmsg: %s\n", scion_strerror((int)nread));
			}

			break;
		}

		path.local.addrlen = c->local_addrlen;
		path.local.addr = (struct sockaddr *)&c->local_addr;

		path.remote.addrlen = addrlen;
		path.remote.addr = (struct sockaddr *)&addr;

		rv = ngtcp2_conn_read_pkt(c->conn, &path, &pi, buf, (size_t)nread, timestamp());
		if (rv != 0) {
			fprintf(stderr, "ngtcp2_conn_read_pkt: %s\n", ngtcp2_strerror(rv));
			if (!c->last_error.error_code) {
				if (rv == NGTCP2_ERR_CRYPTO) {
					ngtcp2_ccerr_set_tls_alert(&c->last_error, ngtcp2_conn_get_tls_alert(c->conn), NULL, 0);
				} else {
					ngtcp2_ccerr_set_liberr(&c->last_error, rv, NULL, 0);
				}
			}
			return -1;
		}
	}

	return 0;
}

static int client_send_packet(struct client *c, const uint8_t *data, size_t datalen)
{
	int nwrite = scion_send(c->socket, data, datalen, 0);

	if (nwrite < 0) {
		printf("ERROR: could not send message (code: %d)\n", nwrite);

		return nwrite;
	}

	return 0;
}

static size_t client_get_message(struct client *c, int64_t *pstream_id, int *pfin, ngtcp2_vec *datav, size_t datavcnt)
{
	if (datavcnt == 0) {
		return 0;
	}

	if (c->stream.stream_id != -1 && c->stream.nwrite < c->stream.datalen) {
		*pstream_id = c->stream.stream_id;
		*pfin = 1;
		datav->base = (uint8_t *)c->stream.data + c->stream.nwrite;
		datav->len = c->stream.datalen - c->stream.nwrite;
		return 1;
	}

	*pstream_id = -1;
	*pfin = 0;
	datav->base = NULL;
	datav->len = 0;

	return 0;
}

static int client_write_streams(struct client *c)
{
	ngtcp2_tstamp ts = timestamp();
	ngtcp2_pkt_info pi;
	ngtcp2_ssize nwrite;
	uint8_t buf[1452];
	ngtcp2_path_storage ps;
	ngtcp2_vec datav;
	size_t datavcnt;
	int64_t stream_id;
	ngtcp2_ssize wdatalen;
	uint32_t flags;
	int fin;

	ngtcp2_path_storage_zero(&ps);

	for (;;) {
		datavcnt = client_get_message(c, &stream_id, &fin, &datav, 1);

		flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
		if (fin) {
			flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;
		}

		nwrite = ngtcp2_conn_writev_stream(
			c->conn, &ps.path, &pi, buf, sizeof(buf), &wdatalen, flags, stream_id, &datav, datavcnt, ts);
		if (nwrite < 0) {
			switch (nwrite) {
			case NGTCP2_ERR_WRITE_MORE:
				c->stream.nwrite += (size_t)wdatalen;
				continue;
			default:
				fprintf(stderr, "ngtcp2_conn_writev_stream: %s\n", ngtcp2_strerror((int)nwrite));
				ngtcp2_ccerr_set_liberr(&c->last_error, (int)nwrite, NULL, 0);
				return -1;
			}
		}

		if (nwrite == 0) {
			return 0;
		}

		if (wdatalen > 0) {
			c->stream.nwrite += (size_t)wdatalen;
		}

		if (client_send_packet(c, buf, (size_t)nwrite) != 0) {
			break;
		}
	}

	return 0;
}

static int client_write(struct client *c)
{
	ngtcp2_tstamp expiry, now;
	ev_tstamp t;

	if (client_write_streams(c) != 0) {
		return -1;
	}

	expiry = ngtcp2_conn_get_expiry(c->conn);
	now = timestamp();

	t = expiry < now ? 1e-9 : (ev_tstamp)(expiry - now) / NGTCP2_SECONDS;

	c->timer.repeat = t;
	ev_timer_again(EV_DEFAULT, &c->timer);

	return 0;
}

static int client_handle_expiry(struct client *c)
{
	int rv = ngtcp2_conn_handle_expiry(c->conn, timestamp());
	if (rv != 0) {
		fprintf(stderr, "ngtcp2_conn_handle_expiry: %s\n", ngtcp2_strerror(rv));
		return -1;
	}

	return 0;
}

static void client_close(struct client *c)
{
	ngtcp2_ssize nwrite;
	ngtcp2_pkt_info pi;
	ngtcp2_path_storage ps;
	uint8_t buf[1280];

	if (ngtcp2_conn_in_closing_period(c->conn) || ngtcp2_conn_in_draining_period(c->conn)) {
		goto fin;
	}

	ngtcp2_path_storage_zero(&ps);

	nwrite = ngtcp2_conn_write_connection_close(c->conn, &ps.path, &pi, buf, sizeof(buf), &c->last_error, timestamp());
	if (nwrite < 0) {
		fprintf(stderr, "ngtcp2_conn_write_connection_close: %s\n", ngtcp2_strerror((int)nwrite));
		goto fin;
	}

	client_send_packet(c, buf, (size_t)nwrite);

fin:
	ev_break(EV_DEFAULT, EVBREAK_ALL);
}

static void read_cb(struct ev_loop *loop, ev_io *w, int revents)
{
	struct client *c = w->data;
	(void)loop;
	(void)revents;

	if (client_read(c) != 0) {
		client_close(c);
		return;
	}

	if (client_write(c) != 0) {
		client_close(c);
	}
}

static void timer_cb(struct ev_loop *loop, ev_timer *w, int revents)
{
	struct client *c = w->data;
	(void)loop;
	(void)revents;

	if (client_handle_expiry(c) != 0) {
		client_close(c);
		return;
	}

	if (client_write(c) != 0) {
		client_close(c);
	}
}

static ngtcp2_conn *get_conn(ngtcp2_crypto_conn_ref *conn_ref)
{
	struct client *c = conn_ref->user_data;
	return c->conn;
}

static int client_init(struct client *c)
{
	int ret;

	struct sockaddr_storage remote_addr, local_addr;
	socklen_t remote_addrlen, local_addrlen = sizeof(local_addr);

	memset(c, 0, sizeof(*c));

	ngtcp2_ccerr_default(&c->last_error);

	ret = create_network(SCION_TOPO_PATH, &c->network, &c->topology);
	if (ret != 0) {
		printf("create_network: could not create network (code: %d)\n", ret);
		goto error;
	}

	ret = create_sock(
		(struct sockaddr *)&remote_addr, &remote_addrlen, &c->socket, REMOTE_HOST, REMOTE_PORT, c->network);
	if (ret != 0) {
		printf("create_sock: could not create socket (code: %d)\n", ret);
		goto cleanup_network;
	}

	ret = connect_sock((struct sockaddr *)&local_addr, &local_addrlen, c->socket, (struct sockaddr *)&remote_addr,
		remote_addrlen, REMOTE_AS);
	if (ret != 0) {
		printf("connect_sock: could not connect socket (code: %d)\n", ret);
		goto cleanup_socket;
	}

	memcpy(&c->local_addr, &local_addr, sizeof(c->local_addr));
	c->local_addrlen = local_addrlen;

	if (client_ssl_init(c) != 0) {
		goto cleanup_socket;
	}

	if (client_quic_init(
			c, (struct sockaddr *)&remote_addr, remote_addrlen, (struct sockaddr *)&local_addr, local_addrlen)
		!= 0) {
		goto cleanup_ssl;
	}

	c->stream.stream_id = -1;

	c->conn_ref.get_conn = get_conn;
	c->conn_ref.user_data = c;

	int socket_fd;
	ret = scion_getsockfd(c->socket, &socket_fd);
	if (ret != 0) {
		printf("scion_getsockfd: could not get socket fd (code: %d)\n", ret);
		goto cleanup_conn;
	}

	ev_io_init(&c->rev, read_cb, socket_fd, EV_READ);
	c->rev.data = c;
	ev_io_start(EV_DEFAULT, &c->rev);

	ev_timer_init(&c->timer, timer_cb, 0., 0.);
	c->timer.data = c;

	return 0;

cleanup_conn:
	ngtcp2_conn_del(c->conn);

cleanup_ssl:
	SSL_CTX_free(c->ssl_ctx);
	SSL_free(c->ssl);

cleanup_socket:
	scion_close(c->socket);

cleanup_network:
	scion_network_free(c->network);
	scion_topology_free(c->topology);

error:
	return ret;
}

static void client_free(struct client *c)
{
	ngtcp2_conn_del(c->conn);
	SSL_free(c->ssl);
	SSL_CTX_free(c->ssl_ctx);
	scion_close(c->socket);
}

int main(void)
{
	struct client c;

	srandom((unsigned int)timestamp());

	if (client_init(&c) != 0) {
		exit(EXIT_FAILURE);
	}

	if (client_write(&c) != 0) {
		exit(EXIT_FAILURE);
	}

	ev_run(EV_DEFAULT, 0);

	client_free(&c);

	return 0;
}
