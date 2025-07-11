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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <scion/scion.h>

static bool has_nine_hops(struct scion_path *path, void *ctx)
{
	(void)ctx;
	return scion_path_get_numhops(path) == 9;
}

static int compare_mtu(struct scion_path *path_one, struct scion_path *path_two, void *ctx)
{
	(void)ctx;
	uint32_t mtu_one = scion_path_get_metadata(path_one)->mtu;
	uint32_t mtu_two = scion_path_get_metadata(path_two)->mtu;

	return (mtu_one > mtu_two) - (mtu_one < mtu_two);
}

static void policy_fn(struct scion_path_collection *paths, void *ctx)
{
	(void)ctx;
	// only use paths that have exactly nine hops
	scion_path_collection_filter(paths, (struct scion_path_predicate){ .fn = has_nine_hops });
	// sort paths with descending MTU
	scion_path_collection_sort(paths, (struct scion_path_comparator){ .fn = compare_mtu, .ascending = false });
}

int main(int argc, char *argv[])
{
	int ret;

	printf("\nHello SCION on Linux\n\n");

	struct scion_topology *topology;
	ret = scion_topology_from_file(&topology, "../../topology/topology.json");
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
	ret = scion_socket(&scion_sock, SCION_AF_INET, SCION_PROTO_UDP, network);
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

	struct scion_policy policy = { .fn = policy_fn, .ctx = NULL };
	ret = scion_setsockpolicy(scion_sock, policy);
	if (ret != 0) {
		printf("ERROR: Setting socket policy failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	ret = scion_connect(scion_sock, (struct sockaddr *)&dst_addr, sizeof(dst_addr), dst_ia);
	if (ret != 0) {
		printf("ERROR: Socket connect failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
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
