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

#include <arpa/inet.h>
#include <assert.h>
#include <float.h>
#include <getopt.h>
#include <inttypes.h>
#include <scion/scion.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <unistd.h>

static int parse_remote(char *str, scion_ia *ia, struct sockaddr *addr, socklen_t *addrlen)
{
	size_t str_len = strlen(str);
	char *separator = memchr(str, ',', str_len);
	if (separator == NULL) {
		return -1;
	}

	size_t ia_len = (size_t)(separator - str);
	if (scion_ia_parse(str, ia_len, ia) != 0) {
		return -1;
	}

	size_t ip_len = str_len - ia_len - 1;
	if (ip_len == 0) {
		return -1;
	}

	char ip_str[ip_len + 1];
	(void)strcpy(ip_str, str + ia_len + 1);

	if (*addrlen >= sizeof(struct sockaddr_in)
		&& inet_pton(AF_INET, ip_str, &((struct sockaddr_in *)addr)->sin_addr) == 1) {
		((struct sockaddr_in *)addr)->sin_family = AF_INET;
		((struct sockaddr_in *)addr)->sin_port = htons(30041);
		*addrlen = sizeof(struct sockaddr_in);
	} else if (*addrlen >= sizeof(struct sockaddr_in6)
			   && inet_pton(AF_INET6, ip_str, &((struct sockaddr_in6 *)addr)->sin6_addr) == 1) {
		((struct sockaddr_in6 *)addr)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)addr)->sin6_port = htons(30041);
		*addrlen = sizeof(struct sockaddr_in6);
	} else {
		return -1;
	}

	return 0;
}

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
	uint16_t echo_length = scion_scmp_echo_len(&echo_request);

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
	if (send_res < 0) {
		return (int)send_res;
	}

	return 0;
}

static int scion_recv_echo_reply(struct scion_socket *scion_socket, uint16_t seqno, uint8_t *payload, uint16_t length,
	struct timeval *tv, ssize_t *rcv_packet_length)
{
	int ret;
	ssize_t rcv_ret;

	struct scion_scmp_echo echo_reply;
	echo_reply.data_length = length;

	uint16_t echo_length = scion_scmp_echo_len(&echo_reply);
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

		ret = scion_scmp_echo_deserialize(buf, echo_length, &echo_reply);
		if (ret != 0) {
			return ret;
		}

		if (echo_reply.seqno != seqno) {
			// Wrong sequence number
			scion_scmp_echo_free_internal(&echo_reply);
			continue;
		}

		if (echo_reply.data_length != length || (length > 0 && memcmp(echo_reply.data, payload, length) != 0)) {
			// Wrong payload
			scion_scmp_echo_free_internal(&echo_reply);
			continue;
		}

		scion_scmp_echo_free_internal(&echo_reply);
		break;
	}

	*rcv_packet_length = rcv_ret;
	return 0;
}

static int ping(struct scion_socket *socket, struct sockaddr *addr, socklen_t addrlen, scion_ia ia, uint16_t count,
	uint16_t payload_size)
{
	int ret;

	uint8_t *payload = NULL;
	struct timeval start;
	struct timeval end;

	uint16_t packets_sent = 0;
	uint16_t packets_received = 0;
	uint16_t packets_lost = 0;

	struct scion_path *path;
	ret = scion_getsockpath(socket, &path);
	if (ret != 0) {
		return ret;
	}
	(void)printf("\nUsing path:\n  ");
	scion_path_print(path);
	(void)printf("\n");

	if (payload_size > 0) {
		payload = malloc(payload_size);

		if (payload == NULL) {
			ret = SCION_MEM_ALLOC_FAIL;
			return ret;
		}

#ifdef __APPLE__
		arc4random_buf(payload, payload_size);
#else
		ssize_t generated_bytes = getrandom(payload, payload_size, 0x0001 /* GRND_NONBLOCK */);
		if (generated_bytes < payload_size) {
			ret = SCION_GENERIC_ERR;
			goto cleanup_payload;
		}
#endif
	}

	(void)printf("PING ");
	scion_print_addr(addr, ia);
	(void)printf(" pld=%" PRIu16 "B\n", payload_size);

	double max = 0.0;
	double min = DBL_MAX;
	double avg = 0.0;

	for (uint16_t i = 0; i < count; i++) {
		ret = scion_send_echo_request(socket, i, payload, payload_size, &start);
		if (ret != 0) {
			(void)printf("SEND ERROR: seqno=%" PRIu16 ", code=%d\n", i, ret);
			continue;
		}
		packets_sent += 1;

		ssize_t rcv_packet_length = 0;
		ret = scion_recv_echo_reply(socket, i, payload, payload_size, &end, &rcv_packet_length);
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

	if (packets_received == 0) {
		return 1;
	}

	return 0;
}

static void print_help()
{
	printf("Usage:\n");
	printf(" ping [options] <remote> <topology>\n");
	printf("\n");
	printf("Examples:\n");
	printf(" ping -c 3 2-ff00:0:222,fd00:f00d:cafe::7f00:55 topology.json\n");
	printf("\n");
	printf("Options:\n");
	printf(" -c, --count uint16            total number of packets to send\n");
	printf(" -h, --help                    help for ping\n");
	printf(" -l, --local ip                local IP address to listen to\n");
	printf(" -s, --payload-size uint16     number of bytes to be sent in addition to the SCION Header and SCMP echo "
		   "header\n");
	printf("     --timeout seconds         timeout per packet in seconds (default is 1)\n");
	printf("     --dispatcher-network      network still uses dispatchers\n");
}

int main(int argc, char **argv)
{
	int ret = EXIT_SUCCESS;

	uint16_t count = 0;
	char *local_ip = NULL;
	uint16_t payload_size = 0;
	struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
	bool is_dispatcher_network = false;

	char *remote_addr = NULL;
	char *topology_path = NULL;

	const struct option options[] = { { .name = "count", .has_arg = required_argument, .flag = NULL, .val = 'c' },
		{ .name = "help", .has_arg = no_argument, .flag = NULL, .val = 'h' },
		{ .name = "local", .has_arg = required_argument, .flag = NULL, .val = 'l' },
		{ .name = "payload-size", .has_arg = required_argument, .flag = NULL, .val = 's' },
		{ .name = "timeout", .has_arg = required_argument, .flag = NULL, .val = 0 },
		{ .name = "dispatcher-network", .has_arg = no_argument, .flag = NULL, .val = 0 } };

	int c;

	while (true) {
		int option_index = 0;

		c = getopt_long(argc, argv, "c:hl:s:", options, &option_index);

		if (c == -1) {
			break;
		}

		switch (c) {
		case 0: {
			const char *option_name = options[option_index].name;

			if (strcmp(option_name, "timeout") == 0) {
				timeout.tv_sec = (time_t)strtol(optarg, NULL, 10);
			} else if (strcmp(option_name, "dispatcher-network") == 0) {
				is_dispatcher_network = true;
			}
			break;
		}
		case 'c':
			count = (uint16_t)strtol(optarg, NULL, 10);
			break;
		case 'h':
			print_help();
			goto cleanup_args;
		case 'l':
			free(local_ip);
			local_ip = strdup(optarg);
			break;
		case 's':
			payload_size = (uint16_t)strtol(optarg, NULL, 10);
			break;
		default:
			ret = 2;
			// Unexpected option encountered
			goto cleanup_args;
		}
	}

	// no args were provided
	if (optind == 1) {
		print_help();
		ret = 2;
		goto cleanup_args;
	}

	// check that exactly two last arguments remain
	if (optind == argc - 2) {
		remote_addr = strdup(argv[optind]);
		topology_path = strdup(argv[optind + 1]);
	} else {
		// no argument
		if (optind == argc) {
			fprintf(stderr, "./ping: missing argument <remote>\n");
		}

		// one argument
		if (optind >= argc - 1) {
			fprintf(stderr, "./ping: missing argument <topology>\n");
		}

		ret = 2;
		goto cleanup_args;
	}

	struct scion_topology *topology;
	ret = scion_topology_from_file(&topology, topology_path);
	if (ret != 0) {
		fprintf(stderr, "Error: could not create topology (%s, code %d)\n", scion_strerror(ret), ret);
		ret = 2;
		goto cleanup_args;
	}

	struct scion_network *network;
	ret = scion_network(&network, topology);
	if (ret != 0) {
		fprintf(stderr, "Error: could not create network (%s, code %d)\n", scion_strerror(ret), ret);
		ret = 2;
		goto cleanup_topology;
	}

	enum scion_addr_family local_addr_family = scion_network_get_local_addr_family(network);
	assert(local_addr_family == SCION_AF_IPV4 || local_addr_family == SCION_AF_IPV6);

	struct scion_socket *socket;
	ret = scion_socket(&socket, local_addr_family, SCION_PROTO_SCMP, network);
	if (ret != 0) {
		fprintf(stderr, "Error: could not create socket (%s, code %d)\n", scion_strerror(ret), ret);
		ret = 2;
		goto cleanup_network;
	}

	bool debug = true;
	ret = scion_setsockopt(socket, SOL_SOCKET, SCION_SO_DEBUG, &debug, sizeof(debug));
	if (ret != 0) {
		goto cleanup_socket;
	}

	ret = scion_setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
	if (ret != 0) {
		fprintf(stderr, "Error: could not set socket option (%s, code %d)\n", scion_strerror(ret), ret);
		ret = 2;
		goto cleanup_socket;
	}

	struct sockaddr_storage local_addr;
	socklen_t local_addr_len;

	if (local_addr_family == SCION_AF_IPV4) {
		struct sockaddr_in *local_addr_in = (struct sockaddr_in *)&local_addr;
		local_addr_in->sin_family = AF_INET;

		if (local_ip != NULL) {
			if (inet_pton(AF_INET, local_ip, &local_addr_in->sin_addr) != 1) {
				fprintf(stderr, "./ping: the local IP address provided must be a valid IPv4 address\n");
				ret = 2;
				goto cleanup_socket;
			}
		} else {
			local_addr_in->sin_addr.s_addr = htons(INADDR_ANY);
		}

		local_addr_in->sin_port = is_dispatcher_network ? htons(30041) : htons(0);
		local_addr_len = sizeof(*local_addr_in);
	} else {
		struct sockaddr_in6 *local_addr_in6 = (struct sockaddr_in6 *)&local_addr;
		local_addr_in6->sin6_family = AF_INET6;

		if (local_ip != NULL) {
			if (inet_pton(AF_INET6, local_ip, &local_addr_in6->sin6_addr) != 1) {
				fprintf(stderr, "./ping: the local IP address provided must be a valid IPv6 address\n");
				ret = 2;
				goto cleanup_socket;
			}
		} else {
			local_addr_in6->sin6_addr = in6addr_any;
		}

		local_addr_in6->sin6_port = is_dispatcher_network ? htons(30041) : htons(0);
		local_addr_len = sizeof(*local_addr_in6);
	}

	ret = scion_bind(socket, (struct sockaddr *)&local_addr, local_addr_len);
	if (ret != 0) {
		fprintf(stderr, "Error: could not bind socket (%s, code %d)\n", scion_strerror(ret), ret);
		ret = 2;
		goto cleanup_socket;
	}

	struct sockaddr_storage dst_addr = { 0 };
	socklen_t dst_addr_len = sizeof(dst_addr);
	scion_ia dst_ia;
	ret = parse_remote(remote_addr, &dst_ia, (struct sockaddr *)&dst_addr, &dst_addr_len);
	if (ret != 0) {
		fprintf(stderr, "./ping: the remote address is an invalid IA,IP address pair\n");
		ret = 2;
		goto cleanup_socket;
	}

	ret = scion_connect(socket, (struct sockaddr *)&dst_addr, dst_addr_len, dst_ia);
	if (ret != 0) {
		fprintf(stderr, "Error: could not connect socket (%s, code %d)\n", scion_strerror(ret), ret);
		ret = 2;
		goto cleanup_socket;
	}

	ret = ping(socket, (struct sockaddr *)&dst_addr, dst_addr_len, dst_ia, count, payload_size);
	if (ret < 0) {
		fprintf(stderr, "Error: could not ping (%s, code %d)\n", scion_strerror(ret), ret);
		ret = 2;
	}

cleanup_socket:
	scion_close(socket);

cleanup_network:
	scion_network_free(network);

cleanup_topology:
	scion_topology_free(topology);

cleanup_args:
	free(remote_addr);
	free(topology_path);
	free(local_ip);

	return ret;
}
