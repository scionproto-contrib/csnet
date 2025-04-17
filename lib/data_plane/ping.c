// Copyright 2024 ETH Zurich
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
#include <float.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <sys/time.h>
#include <unistd.h>

#include "scion/control_plane/network.h"
#include "scion/data_plane/ping.h"
#include "scion/data_plane/scmp.h"
#include "scion/data_plane/socket.h"
#include "scion/error.h"

#include <assert.h>

static int scion_send_echo_request(
	struct scion_socket *scion_sock, uint16_t seqno, uint8_t *payload, uint16_t length, struct timeval *tv)
{
	assert(scion_sock);
	int ret;

	struct scion_scmp_echo echo_request = { 0 };
	echo_request.type = SCION_ECHO_TYPE_REQUEST;
	echo_request.seqno = seqno;

	struct sockaddr_storage src_addr;
	socklen_t src_addr_len = sizeof(src_addr);
	scion_ia ia;
	ret = scion_getsockname(scion_sock, (struct sockaddr *)&src_addr, &src_addr_len, &ia);
	if (ret != 0) {
		return ret;
	}

	// ID has to be the source port
	if (src_addr.ss_family == AF_INET) {
		// IPv4
		echo_request.id = ntohs(((struct sockaddr_in *)&src_addr)->sin_port);
	} else if (src_addr.ss_family == AF_INET6) {
		// IPv6
		echo_request.id = ntohs(((struct sockaddr_in6 *)&src_addr)->sin6_port);
	}

	echo_request.data = payload;
	echo_request.data_length = length;
	// Total size of serialized echo request
	uint16_t echo_length = SCION_SCMP_ECHO_HDR_LEN + echo_request.data_length;

	// Serialize Echo Request
	uint8_t echo_buffer[echo_length];

	ret = scion_scmp_echo_serialize(&echo_request, echo_buffer, echo_length);
	if (ret != 0) {
		return ret;
	}

	if (tv != NULL) {
		(void)gettimeofday(tv, NULL);
	}

	ssize_t send_res = scion_send(scion_sock, echo_buffer, echo_length, 0);
	if (send_res != echo_length) {
		return (int)send_res;
	}

	return 0;
}

static int scion_recv_echo_reply(struct scion_socket *scion_socket, uint16_t seqno, uint8_t *payload, uint16_t length,
	struct timeval *tv, ssize_t *rcv_packet_length)
{
	int ret;
	ssize_t rcv_ret;
	uint16_t echo_length = SCION_SCMP_ECHO_HDR_LEN + length;
	uint8_t buf[echo_length];

	while (true) {
		rcv_ret = scion_recv(scion_socket, &buf, echo_length, 0);
		(void)gettimeofday(tv, NULL);

		if (rcv_ret < 0) {
			return (int)rcv_ret;
		}

		if (scion_scmp_get_type(buf, echo_length) != 129) {
			// Not an ECHO reply
			continue;
		}

		struct scion_scmp_echo echo_reply;
		ret = scion_scmp_echo_deserialize(buf, echo_length, &echo_reply);
		if (ret != 0) {
			return ret;
		}

		if (echo_reply.seqno != seqno) {
			// Wrong sequence number
			continue;
		}

		if (echo_reply.data_length != length || (length > 0 && memcmp(echo_reply.data, payload, length) != 0)) {
			// Wrong payload
			continue;
		}

		break;
	}

	*rcv_packet_length = rcv_ret;
	return 0;
}

int scion_ping(const struct sockaddr *addr, socklen_t addrlen, scion_ia ia, struct scion_network *network, uint16_t n,
	uint16_t payload_len, struct timeval timeout)
{
	assert(addr);
	assert(network);

	int ret;
	uint8_t *payload = NULL;
	struct timeval start;
	struct timeval end;

	uint16_t packets_sent = 0;
	uint16_t packets_received = 0;
	uint16_t packets_lost = 0;

	struct scion_socket *socket;
	ret = scion_socket(&socket, network->topology->local_addr_family, SCION_PROTO_SCMP, network);
	if (ret != 0) {
		return ret;
	}

	bool debug = true;
	ret = scion_setsockopt(socket, SOL_SOCKET, SCION_SO_DEBUG, &debug, sizeof(debug));
	if (ret != 0) {
		return ret;
	}

	ret = scion_setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
	if (ret != 0) {
		return ret;
	}

	ret = scion_connect(socket, addr, addrlen, ia);
	if (ret != 0) {
		return ret;
	}

	struct scion_path *path;
	ret = scion_getsockpath(socket, &path);
	if (ret != 0) {
		return ret;
	}
	(void)printf("\nUsing path:\n  ");
	scion_path_print(path);
	(void)printf("\n");

	if (payload_len > 0) {
		payload = malloc(payload_len);

		if (payload == NULL) {
			ret = SCION_MALLOC_FAIL;
			goto cleanup_socket;
		}

#ifdef __APPLE__
		arc4random_buf(payload, payload_len);
#else
		ssize_t generated_bytes = getrandom(payload, payload_len, 0x0001 /* GRND_NONBLOCK */);
		if (generated_bytes < payload_len) {
			ret = SCION_GENERIC_ERR;
			goto cleanup_payload;
		}
#endif
	}

	(void)printf("PING ");
	scion_print_addr(addr, ia);
	(void)printf(" pld=%" PRIu16 "B\n", payload_len);

	double max = 0.0;
	double min = DBL_MAX;
	double avg = 0.0;

	for (uint16_t i = 0; i < n; i++) {
		ret = scion_send_echo_request(socket, i, payload, payload_len, &start);
		if (ret != 0) {
			(void)printf("SEND ERROR: seqno=%" PRIu16 "\n", i);
			continue;
		}
		packets_sent += 1;

		ssize_t rcv_packet_length = 0;
		ret = scion_recv_echo_reply(socket, i, payload, payload_len, &end, &rcv_packet_length);
		if (ret < 0) {
			packets_lost += 1;
			(void)printf("TIMEOUT: seqno=%" PRIu16 "\n", i);
		} else {
			packets_received += 1;

			uint64_t start_ms = 1000000 * (uint64_t)start.tv_sec + (uint64_t)start.tv_usec;
			uint64_t end_ms = 1000000 * (uint64_t)end.tv_sec + (uint64_t)end.tv_usec;
			uint64_t diff = end_ms - start_ms;

			double t = (double)diff / 1000.0;

			avg += t;
			if (t < min) {
				min = t;
			}
			if (t > max) {
				max = t;
			}

			(void)printf("%zd bytes from ", rcv_packet_length);
			(void)printf(": scmp_seq=%" PRIu16 " time=%.3fms\n", i, t);
		}
		(void)sleep(1);
	}

	double packet_loss = 0.0;

	if (packets_sent > 0) {
		packet_loss = ((double)packets_lost / (double)packets_sent) * 100.0;
	}

	if (packets_received == 0) {
		min = 0.0;
	} else {
		avg = avg / packets_received;
	}

	(void)printf("\n--- ");
	scion_print_addr(addr, ia);
	(void)printf(" ping statistics ---\n");
	(void)printf("%" PRIu16 " packets transmitted, %" PRIu16 " packets received, %.1f%% packet loss\n", packets_sent,
		packets_received, packet_loss);
	(void)printf("round-trip min/avg/max %.3f/%.3f/%.3f ms\n\n", min, avg, max);

#ifndef __APPLE__
cleanup_payload:
#endif
	free(payload);

cleanup_socket:
	scion_close(socket);

	return ret;
}
