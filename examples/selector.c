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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <scion/scion.h>
#include <scion/scion_path.h>
#include <scion/scion_selector.h>

// A selector that sends each packet over the next path, and skips the paths that are down. The context is the index of
// the path to try first.
static struct scion_path *round_robin_select(
	struct scion_path_collection *paths, const struct scion_path *current, void *ctx)
{
	(void)current;
	size_t *next = ctx;

	size_t num_paths;
	struct scion_path **array = scion_path_collection_as_array(paths, &num_paths);
	if (array == NULL) {
		return NULL;
	}

	// Use the next path that is not down, or the next path if all are down
	size_t chosen = *next % num_paths;
	for (size_t i = 0; i < num_paths; i++) {
		size_t candidate = (*next + i) % num_paths;
		if (!scion_path_is_down(array[candidate])) {
			chosen = candidate;
			break;
		}
	}
	*next = chosen + 1;

	struct scion_path *path = array[chosen];
	free(array);

	printf("[Selector] the packet goes over path %zu of %zu\n", chosen, num_paths);
	return path;
}

int main(int argc, char *argv[])
{
	int ret;

	printf("\nHello SCION on Linux\n\n");

	struct scion_topology *topology;
	ret = scion_topology_from_file(&topology, "../topology/topology.json");
	if (ret != 0) {
		printf("ERROR: Topology init failed with error code: %d\n", ret);
		return EXIT_FAILURE;
	}

	struct scion_network *network;
	ret = scion_network(&network, topology);
	if (ret != 0) {
		printf("ERROR: Network init failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_topology;
	}

	struct sockaddr_in6 dst_addr;
	dst_addr.sin6_family = AF_INET6;
	dst_addr.sin6_port = htons(31000);
	inet_pton(AF_INET6, "fd00:f00d:cafe::7f00:55", &dst_addr.sin6_addr);
	scion_ia dst_ia = 0x2ff0000000222;

	struct scion_socket *scion_sock;
	ret = scion_socket(&scion_sock, SCION_AF_INET, SCION_SOCK_DGRAM, SCION_PROTO_UDP, network);
	if (ret != 0) {
		printf("ERROR: Socket setup failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_network;
	}

	int optval = true;
	ret = scion_setsockopt(scion_sock, SOL_SOCKET, SCION_SO_DEBUG, &optval, sizeof(optval));
	if (ret != 0) {
		printf("ERROR: Setting socket to debug mode failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	size_t next_path = 0;
	struct scion_selector selector = { .fn = round_robin_select, .ctx = &next_path };
	ret = scion_setsockselector(scion_sock, &selector);
	if (ret != 0) {
		printf("ERROR: Setting socket selector failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	ret = scion_connect(scion_sock, (struct sockaddr *)&dst_addr, sizeof(dst_addr), dst_ia);
	if (ret != 0) {
		printf("ERROR: Socket connect failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	// ### Send and Receive ###
	// Every packet asks the selector for its path, so the packets use different paths
	for (int i = 1; i <= 3; i++) {
		char tx_buf[] = "Hello, Scion! (from Linux)";
		ret = scion_send(scion_sock, tx_buf, sizeof tx_buf - 1, /* flags: */ 0);
		if (ret < 0) {
			printf("ERROR: Send failed with error code: %d\n", ret);
			ret = EXIT_FAILURE;
			goto cleanup_socket;
		}
		printf("[Sent packet %d, %d bytes]: \"%s\"\n", i, ret, tx_buf);

		char rx_buf[200];
		ret = scion_recv(scion_sock, &rx_buf, sizeof rx_buf - 1, /* flags: */ 0);
		if (ret < 0) {
			printf("ERROR: Receive failed with error code: %d\n", ret);
			ret = EXIT_FAILURE;
			goto cleanup_socket;
		}
		rx_buf[ret] = '\0';
		printf("[Received %d bytes]: \"%s\"\n\n", ret, rx_buf);
	}

	printf("\nDone.\n");
	ret = EXIT_SUCCESS;

cleanup_socket:
	scion_close(scion_sock);

cleanup_network:
	scion_network_free(network);

cleanup_topology:
	scion_topology_free(topology);

	return ret;
}
