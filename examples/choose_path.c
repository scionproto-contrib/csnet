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
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include <scion/scion.h>

static bool select_path(struct scion_path *path, void *ctx)
{
	const struct scion_path_metadata *metadata = scion_path_get_metadata(path);
	return scion_path_get_hops(path) == 8 && metadata->mtu == 1400;
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
	ret = scion_socket(&scion_sock, SCION_AF_IPV4, SCION_PROTO_UDP, network);
	if (ret != 0) {
		printf("ERROR: Socket setup failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_network;
	}

	// ### Select path and set path ###
	struct scion_path_collection *paths;
	ret = scion_fetch_paths(network, dst_ia, SCION_FETCH_OPT_DEBUG, &paths);
	if (ret != 0) {
		printf("ERROR: Failed to fetch paths with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	struct scion_path *path = scion_path_collection_find(paths, (struct scion_path_predicate){ .fn = select_path });
	if (path == NULL) {
		printf("ERROR: Failed to find path meeting criteria\n");
		ret = EXIT_FAILURE;
		goto cleanup_paths;
	}

	// ### Send and Receive ###
	char tx_buf[] = "Hello, Scion!";
	printf("Using Path:\n");
	scion_path_print(path);
	ret = scion_sendto(scion_sock, tx_buf, sizeof tx_buf - 1, /* flags: */ 0, (struct sockaddr *)&dst_addr,
		sizeof(dst_addr), dst_ia, path);
	if (ret < 0) {
		printf("ERROR: Send failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_paths;
	}
	printf("[Sent %d bytes]: \"%s\"\n", ret, tx_buf);

	char rx_buf[200];
	ret = scion_recv(scion_sock, &rx_buf, sizeof rx_buf - 1, /* flags: */ 0);
	if (ret < 0) {
		printf("ERROR: Receive failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_paths;
	}
	rx_buf[ret] = '\0';

	printf("[Received %d bytes]: \"%s\"\n", ret, rx_buf);

	ret = EXIT_SUCCESS;

cleanup_paths:
	scion_path_collection_free(paths);

cleanup_socket:
	scion_close(scion_sock);

cleanup_network:
	scion_network_free(network);

cleanup_topology:
	scion_topology_free(topology);

	return ret;
}
