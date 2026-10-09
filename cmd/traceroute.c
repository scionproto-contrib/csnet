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
#include <assert.h>
#include <getopt.h>
#include <inttypes.h>
#include <scion/scion.h>
#include <scion/scion_scmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include "util/addr.h"

static void print_scmp_error(const struct scion_scmp_error *error, void *ctx)
{
	(void)ctx;

	scion_scmp_error_print(error);
}

// The traceroute reply of a router is sent to the port that is in the identifier of the request.
static int get_local_port(struct scion_socket *scion_sock, uint16_t *port)
{
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	int ret = scion_getsockname(scion_sock, (struct sockaddr *)&addr, &addr_len, NULL);
	if (ret != 0) {
		return ret;
	}

	if (addr.ss_family == AF_INET) {
		*port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
	} else if (addr.ss_family == AF_INET6) {
		*port = ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
	} else {
		return SCION_ERR_ADDR_FAMILY_UNKNOWN;
	}

	return 0;
}

static int send_traceroute_request(struct scion_socket *scion_sock, struct scion_path *path,
	const struct sockaddr *dst_addr, socklen_t dst_addr_len, scion_ia dst_ia, uint16_t id, uint16_t seqno,
	struct timeval *tv)
{
	struct scion_scmp_traceroute request = { .type = SCION_SCMP_TYPE_TRACEROUTE_REQUEST, .id = id, .seqno = seqno };

	uint8_t buf[SCION_SCMP_TRACEROUTE_LEN];
	int ret = scion_scmp_traceroute_serialize(&request, buf, sizeof(buf));
	if (ret != 0) {
		return ret;
	}

	gettimeofday(tv, NULL);

	ssize_t sent = scion_sendto(scion_sock, buf, sizeof(buf), 0, dst_addr, dst_addr_len, dst_ia, path);
	if (sent < 0) {
		return (int)sent;
	}

	return 0;
}

static int recv_traceroute_reply(struct scion_socket *scion_sock, uint16_t id, uint16_t seqno,
	struct scion_scmp_traceroute *reply, struct sockaddr_storage *src_addr, struct timeval *tv)
{
	while (true) {
		uint8_t buf[1500];
		socklen_t src_addr_len = sizeof(*src_addr);

		ssize_t received = scion_recvfrom(scion_sock, buf, sizeof(buf), 0, (struct sockaddr *)src_addr, &src_addr_len,
			NULL, NULL);
		gettimeofday(tv, NULL);

		if (received < 0) {
			return (int)received;
		}

		if (scion_scmp_get_type(buf, (uint16_t)received) != SCION_SCMP_TYPE_TRACEROUTE_REPLY) {
			continue;
		}

		if (scion_scmp_traceroute_deserialize(buf, (size_t)received, reply) != 0) {
			continue;
		}

		// A late reply to an earlier request
		if (reply->id != id || reply->seqno != seqno) {
			continue;
		}

		return 0;
	}
}

static void print_ip(const struct sockaddr_storage *addr)
{
	char str[INET6_ADDRSTRLEN];

	if (addr->ss_family == AF_INET) {
		inet_ntop(AF_INET, &((const struct sockaddr_in *)addr)->sin_addr, str, sizeof(str));
	} else {
		inet_ntop(AF_INET6, &((const struct sockaddr_in6 *)addr)->sin6_addr, str, sizeof(str));
	}

	printf("%s", str);
}

static int traceroute(struct scion_socket *scion_sock, struct scion_path *path, const struct sockaddr *dst_addr,
	socklen_t dst_addr_len, scion_ia dst_ia, uint16_t id)
{
	const struct scion_path_metadata *metadata = scion_path_get_metadata(path);

	printf("\nUsing path:\n  ");
	scion_path_print(path);
	printf("\n");

	printf("Traceroute to ");
	scion_ia_print(dst_ia);
	printf("\n");

	if (metadata == NULL || metadata->interfaces_len == 0) {
		printf("The path has no interfaces, the destination is in the local AS.\n");
		return 0;
	}

	size_t replies = 0;

	for (size_t i = 0; i < metadata->interfaces_len; i++) {
		int ret = scion_path_set_router_alert(path, i);
		if (ret != 0) {
			return ret;
		}

		struct timeval start;
		ret = send_traceroute_request(scion_sock, path, dst_addr, dst_addr_len, dst_ia, id, (uint16_t)i, &start);
		if (ret != 0) {
			printf("%2zu SEND ERROR: %s (code %d)\n", i, scion_strerror(ret), ret);
			continue;
		}

		struct scion_scmp_traceroute reply;
		struct sockaddr_storage src_addr;
		struct timeval end;
		ret = recv_traceroute_reply(scion_sock, id, (uint16_t)i, &reply, &src_addr, &end);
		if (ret != 0) {
			printf("%2zu *\n", i);
			continue;
		}
		replies++;

		uint64_t start_us = 1000000 * (uint64_t)start.tv_sec + (uint64_t)start.tv_usec;
		uint64_t end_us = 1000000 * (uint64_t)end.tv_sec + (uint64_t)end.tv_usec;

		printf("%2zu ", i);
		scion_ia_print(reply.ia);
		printf(",");
		print_ip(&src_addr);
		printf(" IfID=%" PRIu64 " %.3fms\n", reply.interface, (double)(end_us - start_us) / 1000.0);
	}

	printf("\n");

	return replies == 0 ? 1 : 0;
}

static void print_help(void)
{
	printf("Usage:\n");
	printf(" traceroute [options] <remote> <topology>\n");
	printf("\n");
	printf("Examples:\n");
	printf(" traceroute 2-ff00:0:222,fd00:f00d:cafe::7f00:55 topology.json\n");
	printf("\n");
	printf("Options:\n");
	printf(" -h, --help                    help for traceroute\n");
	printf(" -l, --local ip                local IP address to listen to\n");
	printf("     --timeout seconds         timeout per packet in seconds (default is 1)\n");
	printf("     --dispatcher-network      network still requires dispatchers (ensures traceroute uses local port "
		   "30041)\n");
}

int main(int argc, char **argv)
{
	int ret = EXIT_SUCCESS;

	char *local_ip = NULL;
	struct timeval timeout = { .tv_sec = 1, .tv_usec = 0 };
	bool is_dispatcher_network = false;

	char *remote_addr = NULL;
	char *topology_path = NULL;

	const struct option options[] = { { .name = "help", .has_arg = no_argument, .flag = NULL, .val = 'h' },
		{ .name = "local", .has_arg = required_argument, .flag = NULL, .val = 'l' },
		{ .name = "timeout", .has_arg = required_argument, .flag = NULL, .val = 0 },
		{ .name = "dispatcher-network", .has_arg = no_argument, .flag = NULL, .val = 0 }, { 0 } };

	while (true) {
		int option_index = 0;

		int c = getopt_long(argc, argv, "hl:", options, &option_index);

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
		case 'h':
			print_help();
			goto cleanup_args;
		case 'l':
			free(local_ip);
			local_ip = strdup(optarg);
			break;
		default:
			ret = 2;
			// Unexpected option encountered
			goto cleanup_args;
		}
	}

	// no args were provided
	if (argc == 1) {
		print_help();
		ret = 2;
		goto cleanup_args;
	}

	// check that exactly two last arguments remain
	if (optind != argc - 2) {
		if (optind > argc - 2) {
			if (optind == argc) {
				fprintf(stderr, "./traceroute: missing argument <remote>\n");
			}
			fprintf(stderr, "./traceroute: missing argument <topology>\n");
		} else {
			fprintf(stderr, "./traceroute: too many arguments\n");
		}

		ret = 2;
		goto cleanup_args;
	}

	remote_addr = strdup(argv[optind]);
	topology_path = strdup(argv[optind + 1]);

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
	assert(local_addr_family == SCION_AF_INET || local_addr_family == SCION_AF_INET6);

	// The socket is not connected, as the routers that answer are not the destination.
	struct scion_socket *socket;
	ret = scion_socket(&socket, local_addr_family, SCION_SOCK_RAW, SCION_PROTO_SCMP, network);
	if (ret != 0) {
		fprintf(stderr, "Error: could not create socket (%s, code %d)\n", scion_strerror(ret), ret);
		ret = 2;
		goto cleanup_network;
	}

	ret = scion_setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
	if (ret != 0) {
		fprintf(stderr, "Error: could not set socket option (%s, code %d)\n", scion_strerror(ret), ret);
		ret = 2;
		goto cleanup_socket;
	}

	ret = scion_setsockerrcb(socket, print_scmp_error, NULL);
	if (ret != 0) {
		fprintf(stderr, "Error: could not set SCMP error callback (%s, code %d)\n", scion_strerror(ret), ret);
		ret = 2;
		goto cleanup_socket;
	}

	struct sockaddr_storage local_addr;
	socklen_t local_addr_len;
	ret = scion_addr_from_ip(
		local_addr_family, local_ip, is_dispatcher_network ? 30041 : 0, &local_addr, &local_addr_len);
	if (ret != 0) {
		fprintf(stderr, "./traceroute: the local IP address provided must be a valid IPv%d address\n",
			local_addr_family == SCION_AF_INET ? 4 : 6);
		ret = 2;
		goto cleanup_socket;
	}

	ret = scion_bind(socket, (struct sockaddr *)&local_addr, local_addr_len);
	if (ret != 0) {
		fprintf(stderr, "Error: could not bind socket (%s, code %d)\n", scion_strerror(ret), ret);
		ret = 2;
		goto cleanup_socket;
	}

	uint16_t id;
	ret = get_local_port(socket, &id);
	if (ret != 0) {
		fprintf(stderr, "Error: could not get the local port (%s, code %d)\n", scion_strerror(ret), ret);
		ret = 2;
		goto cleanup_socket;
	}

	struct sockaddr_storage dst_addr = { 0 };
	socklen_t dst_addr_len = sizeof(dst_addr);
	scion_ia dst_ia;
	ret = scion_addr_parse(remote_addr, 30041, &dst_ia, (struct sockaddr *)&dst_addr, &dst_addr_len);
	if (ret != 0) {
		fprintf(stderr, "./traceroute: the remote address is an invalid IA,IP address pair\n");
		ret = 2;
		goto cleanup_socket;
	}

	struct scion_path_collection *paths;
	ret = scion_path_collection_fetch(network, dst_ia, SCION_FETCH_OPT_DEBUG, &paths);
	if (ret != 0) {
		fprintf(stderr, "Error: could not fetch paths (%s, code %d)\n", scion_strerror(ret), ret);
		ret = 2;
		goto cleanup_socket;
	}

	struct scion_path *path = scion_path_collection_pop(paths);
	if (path == NULL) {
		fprintf(stderr, "Error: no paths available to destination\n");
		ret = 2;
		goto cleanup_paths;
	}

	ret = traceroute(socket, path, (struct sockaddr *)&dst_addr, dst_addr_len, dst_ia, id);
	if (ret < 0) {
		fprintf(stderr, "Error: could not traceroute (%s, code %d)\n", scion_strerror(ret), ret);
		ret = 2;
	}

	scion_path_free(path);

cleanup_paths:
	scion_path_collection_free(paths);

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
