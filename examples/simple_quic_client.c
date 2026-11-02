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

// A QUIC client over SCION with the scion_quic library: sends a message on a bidirectional stream, finishes the
// stream and prints the answer of the server. By default it talks to the helloquic server of scion-apps
// (scripts/run-quic-server.sh), which answers "gotcha: <message>". It runs on Linux (main() below) and on the ESP32
// (esp32/main/main.c calls simple_quic_client()).

#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>

#include <scion/scion.h>
#include <scion/scion_quic.h>

#include "simple_quic_client.h"

#define REMOTE_AS "2-ff00:0:222"
#define REMOTE_HOST "fd00:f00d:cafe::7f00:55"
#define REMOTE_PORT 31003
#define REMOTE_AF SCION_AF_INET6
#define ALPN "hello-quic"
#define MESSAGE "Hello QUIC"
#define SCION_TOPO_PATH "../topology/topology.json"
#define TIMEOUT_MS 10000

// Milliseconds
static uint64_t timestamp(void)
{
	struct timespec tp;

	if (clock_gettime(CLOCK_MONOTONIC, &tp) != 0) {
		fprintf(stderr, "clock_gettime: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}

	return (uint64_t)tp.tv_sec * 1000 + (uint64_t)tp.tv_nsec / 1000000;
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

static void create_addr(struct sockaddr *addr, socklen_t *paddrlen, const char *host, uint16_t port)
{
	if (REMOTE_AF == SCION_AF_INET) {
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
}

// Opens a SCION socket, connects it and runs the QUIC handshake (scion_quic owns the socket).
static int connect_conn(struct scion_quic_conn **conn, struct scion_network *network,
	const struct sockaddr *remote_addr, socklen_t remote_addrlen, const char *remote_ia,
	const struct scion_quic_config *config)
{
	scion_ia ia;
	int ret = scion_ia_parse(remote_ia, strlen(remote_ia), &ia);
	if (ret != 0) {
		return ret;
	}

	return scion_quic_connect(conn, network, remote_addr, remote_addrlen, ia, config);
}

struct client {
	struct scion_topology *topology;
	struct scion_network *network;
	struct scion_quic_conn *conn;
	uint64_t start;
};

static int client_init(struct client *c, const char *topology_path, const struct scion_quic_config *config)
{
	int ret;

	struct sockaddr_storage remote_addr;
	socklen_t remote_addrlen;
	struct scion_quic_config quic_config = *config;

	memset(c, 0, sizeof(*c));
	memset(&remote_addr, 0, sizeof(remote_addr));
	quic_config.alpn = ALPN;

	ret = create_network(topology_path, &c->network, &c->topology);
	if (ret != 0) {
		printf("create_network: could not create network (code: %d)\n", ret);
		goto error;
	}

	create_addr((struct sockaddr *)&remote_addr, &remote_addrlen, REMOTE_HOST, REMOTE_PORT);

	c->start = timestamp();
	ret = connect_conn(&c->conn, c->network, (struct sockaddr *)&remote_addr, remote_addrlen, REMOTE_AS, &quic_config);
	if (ret != 0) {
		printf("connect_conn: could not connect (code: %d)\n", ret);
		goto cleanup_network;
	}

	// The message is queued and sent as soon as the handshake is done, then the stream is finished.
	ssize_t nwrite = scion_quic_write(c->conn, MESSAGE, sizeof(MESSAGE) - 1);
	if (nwrite < 0) {
		ret = (int)nwrite;
		printf("scion_quic_write: could not write (code: %d)\n", ret);
		goto cleanup_conn;
	}

	ret = scion_quic_shutdown(c->conn);
	if (ret != 0) {
		printf("scion_quic_shutdown: could not finish the stream (code: %d)\n", ret);
		goto cleanup_conn;
	}

	return 0;

cleanup_conn:
	scion_quic_close(c->conn);

cleanup_network:
	scion_network_free(c->network);
	scion_topology_free(c->topology);

error:
	return ret;
}

// Reads the answer of the server until it finishes the stream.
static int client_read(struct client *c)
{
	char buf[512];
	size_t len = 0;
	bool established = false;
	ssize_t nread;
	int ret;

	for (;;) {
		ret = scion_quic_wait(c->conn, 100);
		if (ret != 0 && ret != SCION_ERR_QUIC_CLOSED) {
			printf("scion_quic_wait: connection failed (code: %d)\n", ret);
			return ret;
		}

		if (!established && scion_quic_is_established(c->conn)) {
			established = true;
			printf(
				"QUIC handshake done (%llu ms), sent \"%s\"\n", (unsigned long long)(timestamp() - c->start), MESSAGE);
		}

		nread = scion_quic_read(c->conn, buf + len, sizeof(buf) - 1 - len);
		if (nread > 0) {
			len += (size_t)nread;
			continue;
		}

		if (nread == 0 || len == sizeof(buf) - 1) {
			break;
		}

		if (nread != SCION_ERR_WOULD_BLOCK) {
			printf("scion_quic_read: could not read (code: %d)\n", (int)nread);
			return (int)nread;
		}

		if (timestamp() - c->start > TIMEOUT_MS) {
			printf("ERROR: no answer after %d ms\n", TIMEOUT_MS);
			return SCION_ERR_TIMEOUT;
		}
	}

	buf[len] = '\0';
	printf("received \"%s\" (%llu ms)\n", buf, (unsigned long long)(timestamp() - c->start));

	return 0;
}

static void client_free(struct client *c)
{
	scion_quic_close(c->conn);
	scion_network_free(c->network);
	scion_topology_free(c->topology);
}

int simple_quic_client(const char *topology_path, const struct scion_quic_config *config)
{
	struct client c;

	int ret = client_init(&c, topology_path, config);
	if (ret != 0) {
		return ret;
	}

	ret = client_read(&c);

	client_free(&c);

	return ret;
}

#ifndef ESP_PLATFORM
#include <unistd.h>

static char *read_file(const char *path, size_t *len)
{
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

int main(int argc, char **argv)
{
	const char *topology_path = SCION_TOPO_PATH;
	struct scion_quic_config config = { 0 };
	char *ca = NULL;
	int opt;

	while ((opt = getopt(argc, argv, "t:c:s:d")) != -1) {
		switch (opt) {
		case 't': // topology.json of the local AS
			topology_path = optarg;
			break;
		case 'c': // verify the server with these CA certificates (PEM)
			ca = read_file(optarg, &config.ca_pem_len);
			if (!ca) {
				fprintf(stderr, "could not read %s\n", optarg);
				exit(EXIT_FAILURE);
			}
			config.ca_pem = ca;
			break;
		case 's': // server name (SNI), checked against the certificate with -c
			config.server_name = optarg;
			break;
		case 'd': // QUIC packet log
			config.debug = true;
			break;
		default:
			fprintf(stderr, "Usage: %s [-t topology.json] [-c ca.pem] [-s server_name] [-d]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (simple_quic_client(topology_path, &config) != 0) {
		free(ca);
		exit(EXIT_FAILURE);
	}

	free(ca);

	return 0;
}
#endif
