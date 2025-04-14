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
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <scion/scion.h>

int main(int argc, char *argv[])
{
	int ret;

	printf("\nHello SCION on Linux\n");

	struct scion_topology *topology;
	ret = scion_topology_from_file(&topology, "topology.json");
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
	inet_pton(AF_INET6, "fd00:f00d:cafe::7f00:55", &dst_addr.sin6_addr);
	scion_ia dst_ia = 0x2ff0000000222;

	// ### PING ###
	struct timeval timeout = { .tv_sec = 1 };
	ret = scion_ping(
		(struct sockaddr *)&dst_addr, sizeof(dst_addr), dst_ia, network, /* n: */ 3, /* payload_len: */ 0, timeout);
	if (ret != 0) {
		printf("ERROR: Ping failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_network;
	}

	ret = EXIT_SUCCESS;
	printf("Done.\n");

cleanup_network:
	scion_network_free(network);

cleanup_topology:
	scion_topology_free(topology);

	return ret;
}
