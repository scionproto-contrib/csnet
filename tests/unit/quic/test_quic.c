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

// Tests of scion_quic against the in-process server of quic_test_server.c, over SCION in the local AS (loopback).

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cmocka.h>

#include "data_plane/socket_fixture.h"
#include "quic_test_server.h"
#include "scion/scion.h"
#include "scion/scion_quic.h"
#include "test_quic.h"

#define TIMEOUT_MS 5000

static uint64_t now_ms(void)
{
	struct timespec tp;
	clock_gettime(CLOCK_MONOTONIC, &tp);
	return (uint64_t)tp.tv_sec * 1000 + (uint64_t)tp.tv_nsec / 1000000;
}

static struct scion_quic_conn *connect_to(
	struct socket_fixture *fixture, struct quic_test_server *server, const struct scion_quic_config *config)
{
	struct scion_quic_conn *conn = NULL;
	assert_int_equal(scion_quic_connect(&conn, fixture->network, (struct sockaddr *)&server->addr, sizeof(server->addr),
						 local_ia_of(fixture), config),
		0);
	assert_non_null(conn);
	return conn;
}

// Processes the connection until it is established; returns the error if it fails.
static int wait_established(struct scion_quic_conn *conn)
{
	uint64_t start = now_ms();
	while (!scion_quic_is_established(conn)) {
		int ret = scion_quic_wait(conn, 50);
		if (ret != 0) {
			return ret;
		}
		assert_true(now_ms() - start < TIMEOUT_MS);
	}
	return 0;
}

// Reads the stream until the server finished it, reading at most chunk bytes at a time.
static size_t read_all(struct scion_quic_conn *conn, uint8_t *buf, size_t cap, size_t chunk)
{
	size_t len = 0;
	uint64_t start = now_ms();
	for (;;) {
		size_t want = cap - len < chunk ? cap - len : chunk;
		ssize_t n = scion_quic_read(conn, buf + len, want);
		if (n > 0) {
			len += (size_t)n;
			continue;
		}
		if (n == 0) {
			return len;
		}
		assert_int_equal(n, SCION_ERR_WOULD_BLOCK);
		assert_int_equal(scion_quic_wait(conn, 50), 0);
		assert_true(now_ms() - start < TIMEOUT_MS);
	}
}

static struct scion_quic_config verifying_config(const char *ca_file, const char *server_name, char **ca)
{
	size_t len = 0;
	*ca = quic_test_read_file(ca_file, &len);
	assert_non_null(*ca);
	return (struct scion_quic_config){
		.alpn = QUIC_TEST_ALPN, .server_name = server_name, .ca_pem = *ca, .ca_pem_len = len
	};
}

static void test_quic_connect_rejects_invalid_arguments(void **state)
{
	struct socket_fixture *fixture = *state;
	struct sockaddr_in addr = loopback_addr(30001);
	struct scion_quic_conn *conn = NULL;
	struct scion_quic_config config = { .alpn = QUIC_TEST_ALPN };
	scion_ia ia = local_ia_of(fixture);

	assert_int_equal(scion_quic_connect(&conn, fixture->network, (struct sockaddr *)&addr, sizeof(addr), ia, NULL),
		SCION_ERR_GENERIC);
	struct scion_quic_config no_alpn = { 0 };
	assert_int_equal(scion_quic_connect(&conn, fixture->network, (struct sockaddr *)&addr, sizeof(addr), ia, &no_alpn),
		SCION_ERR_GENERIC);
	assert_int_equal(
		scion_quic_connect(&conn, NULL, (struct sockaddr *)&addr, sizeof(addr), ia, &config), SCION_ERR_GENERIC);
	assert_int_equal(scion_quic_connect(&conn, fixture->network, (struct sockaddr *)&addr,
						 sizeof(struct sockaddr_storage) + 1, ia, &config),
		SCION_ERR_GENERIC);
	assert_null(conn);
}

static void test_quic_rejects_invalid_tls_settings(void **state)
{
	struct socket_fixture *fixture = *state;
	struct sockaddr_in addr = loopback_addr(30001);
	struct scion_quic_conn *conn = NULL;
	scion_ia ia = local_ia_of(fixture);

	char long_alpn[300];
	memset(long_alpn, 'a', sizeof(long_alpn) - 1);
	long_alpn[sizeof(long_alpn) - 1] = '\0';
	struct scion_quic_config config = { .alpn = long_alpn };
	assert_int_equal(scion_quic_connect(&conn, fixture->network, (struct sockaddr *)&addr, sizeof(addr), ia, &config),
		SCION_ERR_TLS_SETUP_FAIL);

	const char garbage[] = "-----BEGIN CERTIFICATE-----\nnot a certificate\n-----END CERTIFICATE-----\n";
	config = (struct scion_quic_config){ .alpn = QUIC_TEST_ALPN, .ca_pem = garbage, .ca_pem_len = sizeof(garbage) - 1 };
	assert_int_equal(scion_quic_connect(&conn, fixture->network, (struct sockaddr *)&addr, sizeof(addr), ia, &config),
		SCION_ERR_TLS_SETUP_FAIL);
	assert_null(conn);

	scion_quic_close(NULL); // no-op
}

static void test_quic_round_trip(void **state)
{
	struct socket_fixture *fixture = *state;
	struct quic_test_server server = { .mode = QUIC_TEST_ECHO };
	quic_test_server_start(&server, fixture->network);

	struct scion_quic_config config = { .alpn = QUIC_TEST_ALPN };
	struct scion_quic_conn *conn = connect_to(fixture, &server, &config);

	// Before the handshake: nothing to read, writes are queued.
	assert_false(scion_quic_is_established(conn));
	uint8_t buf[64];
	assert_int_equal(scion_quic_read(conn, buf, sizeof(buf)), SCION_ERR_WOULD_BLOCK);
	assert_int_equal(scion_quic_write(conn, "hello ", 6), 6);
	assert_int_equal(scion_quic_write(conn, "QUIC", 4), 4);
	assert_int_equal(scion_quic_shutdown(conn), 0);
	assert_int_equal(scion_quic_write(conn, "late", 4), SCION_ERR_GENERIC); // after the FIN

	assert_int_equal(wait_established(conn), 0);
	size_t len = read_all(conn, buf, sizeof(buf), sizeof(buf));
	assert_int_equal(len, 16);
	assert_memory_equal(buf, "echo: hello QUIC", 16);
	assert_int_equal(scion_quic_read(conn, buf, sizeof(buf)), 0); // end of stream, again

	scion_quic_close(conn);
	quic_test_server_stop(&server);
	assert_true(server.handshake_done);
	assert_true(server.received_fin);
	assert_int_equal(server.received_len, 10);
	assert_memory_equal(server.received, "hello QUIC", 10);
	quic_test_server_free(&server);
}

static void test_quic_empty_streams(void **state)
{
	struct socket_fixture *fixture = *state;
	struct quic_test_server server = { .mode = QUIC_TEST_EMPTY };
	quic_test_server_start(&server, fixture->network);

	struct scion_quic_config config = { .alpn = QUIC_TEST_ALPN };
	struct scion_quic_conn *conn = connect_to(fixture, &server, &config);
	assert_int_equal(scion_quic_shutdown(conn), 0); // the FIN without data
	uint8_t buf[16];
	assert_int_equal(read_all(conn, buf, sizeof(buf), sizeof(buf)), 0); // the FIN of the server without data

	scion_quic_close(conn);
	quic_test_server_stop(&server);
	assert_true(server.received_fin);
	assert_int_equal(server.received_len, 0);
	quic_test_server_free(&server);
}

static void test_quic_receives_beyond_window(void **state)
{
	struct socket_fixture *fixture = *state;
	// 512 KB: 8 times the stream window and 4 times the connection window of the client
	const size_t bulk = 512 * 1024;
	struct quic_test_server server = { .mode = QUIC_TEST_BULK, .bulk_len = bulk };
	quic_test_server_start(&server, fixture->network);

	struct scion_quic_config config = { .alpn = QUIC_TEST_ALPN };
	struct scion_quic_conn *conn = connect_to(fixture, &server, &config);
	assert_int_equal(scion_quic_shutdown(conn), 0);

	uint8_t *buf = malloc(bulk + 1);
	assert_non_null(buf);
	size_t len = read_all(conn, buf, bulk + 1, 1000); // small reads: the window grows only as the client reads
	assert_int_equal(len, bulk);
	for (size_t i = 0; i < bulk; i++) {
		if (buf[i] != (uint8_t)(i % 251)) {
			fail_msg("byte %zu is %u, expected %u", i, buf[i], (unsigned)(i % 251));
		}
	}
	free(buf);

	scion_quic_close(conn);
	quic_test_server_stop(&server);
	quic_test_server_free(&server);
}

static void test_quic_sends_beyond_server_window(void **state)
{
	struct socket_fixture *fixture = *state;
	// The server allows 16 KB at a time and extends the window as it receives: the client must resume.
	const size_t total = 300 * 1000;
	struct quic_test_server server = { .mode = QUIC_TEST_ECHO, .stream_window = 16 * 1024 };
	quic_test_server_start(&server, fixture->network);

	struct scion_quic_config config = { .alpn = QUIC_TEST_ALPN };
	struct scion_quic_conn *conn = connect_to(fixture, &server, &config);
	uint8_t *data = malloc(total);
	assert_non_null(data);
	for (size_t i = 0; i < total; i++) {
		data[i] = (uint8_t)(i * 7);
	}
	assert_int_equal(scion_quic_write(conn, data, total), (ssize_t)total);
	assert_int_equal(scion_quic_shutdown(conn), 0);

	uint8_t *echo = malloc(total + 7);
	assert_non_null(echo);
	assert_int_equal(read_all(conn, echo, total + 7, 4096), total + 6);
	assert_memory_equal(echo, "echo: ", 6);
	assert_memory_equal(echo + 6, data, total);

	scion_quic_close(conn);
	quic_test_server_stop(&server);
	assert_int_equal(server.received_len, total);
	assert_memory_equal(server.received, data, total);
	quic_test_server_free(&server);
	free(data);
	free(echo);
}

static void test_quic_verifies_the_server(void **state)
{
	struct socket_fixture *fixture = *state;
	struct quic_test_server server = { .mode = QUIC_TEST_ECHO };
	quic_test_server_start(&server, fixture->network);

	char *ca;
	struct scion_quic_config config = verifying_config("ca.pem", QUIC_TEST_SERVER_NAME, &ca);
	struct scion_quic_conn *conn = connect_to(fixture, &server, &config);
	assert_int_equal(scion_quic_write(conn, "verified", 8), 8);
	assert_int_equal(scion_quic_shutdown(conn), 0);
	assert_int_equal(wait_established(conn), 0);
	uint8_t buf[32];
	assert_int_equal(read_all(conn, buf, sizeof(buf), sizeof(buf)), 14);
	assert_memory_equal(buf, "echo: verified", 14);

	scion_quic_close(conn);
	free(ca);
	quic_test_server_stop(&server);
	quic_test_server_free(&server);
}

static void expect_handshake_failure(struct socket_fixture *fixture, const struct scion_quic_config *config)
{
	struct quic_test_server server = { .mode = QUIC_TEST_ECHO };
	quic_test_server_start(&server, fixture->network);

	struct scion_quic_conn *conn = connect_to(fixture, &server, config);
	assert_int_equal(scion_quic_write(conn, "secret", 6), 6);
	assert_int_equal(wait_established(conn), SCION_ERR_QUIC_HANDSHAKE_FAIL);
	assert_false(scion_quic_is_established(conn));
	uint8_t buf[16];
	assert_int_equal(scion_quic_read(conn, buf, sizeof(buf)), SCION_ERR_QUIC_HANDSHAKE_FAIL);
	assert_int_equal(scion_quic_write(conn, "more", 4), SCION_ERR_QUIC_HANDSHAKE_FAIL);
	assert_int_equal(scion_quic_process(conn), SCION_ERR_QUIC_HANDSHAKE_FAIL);

	scion_quic_close(conn);
	quic_test_server_stop(&server);
	assert_int_equal(server.received_len, 0); // no application data reached the server
	quic_test_server_free(&server);
}

static void test_quic_rejects_a_wrong_server_name(void **state)
{
	char *ca;
	struct scion_quic_config config = verifying_config("ca.pem", "other.test", &ca);
	expect_handshake_failure(*state, &config);
	free(ca);
}

static void test_quic_rejects_an_untrusted_certificate(void **state)
{
	char *ca;
	struct scion_quic_config config = verifying_config("other_ca.pem", QUIC_TEST_SERVER_NAME, &ca);
	expect_handshake_failure(*state, &config);
	free(ca);
}

static void test_quic_rejects_a_wrong_alpn(void **state)
{
	struct scion_quic_config config = { .alpn = "other" };
	expect_handshake_failure(*state, &config);
}

static void test_quic_reports_server_close(void **state)
{
	struct socket_fixture *fixture = *state;
	struct quic_test_server server = { .mode = QUIC_TEST_CLOSE };
	quic_test_server_start(&server, fixture->network);

	struct scion_quic_config config = { .alpn = QUIC_TEST_ALPN };
	struct scion_quic_conn *conn = connect_to(fixture, &server, &config);
	int ret = 0;
	uint64_t start = now_ms();
	while (ret == 0) {
		ret = scion_quic_wait(conn, 50);
		assert_true(now_ms() - start < TIMEOUT_MS);
	}
	assert_int_equal(ret, SCION_ERR_QUIC_CLOSED);
	assert_false(scion_quic_is_established(conn));
	uint8_t buf[16];
	assert_int_equal(scion_quic_read(conn, buf, sizeof(buf)), SCION_ERR_QUIC_CLOSED);
	assert_int_equal(scion_quic_write(conn, "x", 1), SCION_ERR_QUIC_CLOSED);
	assert_int_equal(scion_quic_shutdown(conn), SCION_ERR_QUIC_CLOSED);

	scion_quic_close(conn);
	quic_test_server_stop(&server);
	quic_test_server_free(&server);
}

static void test_quic_waits_for_a_silent_server(void **state)
{
	struct socket_fixture *fixture = *state;
	// A bound socket that never answers
	struct scion_socket *silent = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(silent);
	struct sockaddr_in addr = bound_address(silent);

	struct scion_quic_config config = { .alpn = QUIC_TEST_ALPN };
	struct scion_quic_conn *conn = NULL;
	assert_int_equal(scion_quic_connect(&conn, fixture->network, (struct sockaddr *)&addr, sizeof(addr),
						 local_ia_of(fixture), &config),
		0);

	int fd = -1;
	assert_int_equal(scion_quic_getfd(conn, &fd), 0);
	assert_true(fd >= 0);
	int timeout = scion_quic_timeout(conn); // the retransmission timer of the Initial packet
	assert_true(timeout > 0 && timeout <= 1000);

	uint64_t start = now_ms();
	assert_int_equal(scion_quic_wait(conn, 100), 0);
	assert_true(now_ms() - start >= 90); // waited, nothing arrived
	assert_false(scion_quic_is_established(conn));
	assert_int_equal(scion_quic_process(conn), 0);
	uint8_t buf[4];
	assert_int_equal(scion_quic_read(conn, buf, sizeof(buf)), SCION_ERR_WOULD_BLOCK);

	// The Initial packets of the client reach the server (padded to the full datagram size).
	uint8_t packet[2048];
	set_receive_timeout(silent, 2000);
	assert_int_equal(scion_recv(silent, packet, sizeof(packet), 0), 1200);

	scion_quic_close(conn);
}

int run_quic_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_quic_connect_rejects_invalid_arguments, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_quic_rejects_invalid_tls_settings, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_quic_round_trip, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_quic_empty_streams, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_quic_receives_beyond_window, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_quic_sends_beyond_server_window, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_quic_verifies_the_server, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_quic_rejects_a_wrong_server_name, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_quic_rejects_an_untrusted_certificate, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_quic_rejects_a_wrong_alpn, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_quic_reports_server_close, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_quic_waits_for_a_silent_server, setup_fixture, teardown_fixture),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
