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

int main(int argc, char *argv[])
{
	int ret;

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

	struct scion_socket *socket;
	ret = scion_socket(&socket, SCION_AF_INET, SCION_PROTO_UDP, network);
	if (ret != 0) {
		printf("scion_socket failed: (code %d, '%s')\n", ret, scion_strerror(ret));
		ret = EXIT_FAILURE;
		goto cleanup_network;
	}

	char msg[] = "Hello!";

	// Unbound, non-connected socket
	ret = scion_sendto(
		socket, msg, sizeof(msg) - 1, 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr), dst_ia, /* path: */ NULL);
	if (ret < 0) {
		printf("scion_sendto failed: (code %d, '%s')\n", ret, scion_strerror(ret));
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	ret = scion_send(socket, msg, sizeof(msg) - 1, /* flags: */ 0);
	if (ret != SCION_ERR_NOT_CONNECTED) {
		printf("scion_send should have failed, but got: (code %d, '%s')\n", ret, scion_strerror(ret));
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	// Unbound, connected socket
	ret = scion_connect(socket, (struct sockaddr *)&dst_addr, sizeof(dst_addr), dst_ia);
	if (ret != 0) {
		printf("scion_connect failed: (code %d, '%s')\n", ret, scion_strerror(ret));
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	// Bound, connected socket
	ret = scion_send(socket, msg, sizeof(msg) - 1, /* flags: */ 0);
	if (ret < 0) {
		printf("scion_send failed: (code %d, '%s')\n", ret, scion_strerror(ret));
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	int err;
	socklen_t len = sizeof(err);
	ret = scion_getsockopt(socket, SOL_SOCKET, SO_ERROR, &err, &len);
	if (ret != 0) {
		printf("scion_getsockopt failed: (code %d, '%s')\n", ret, scion_strerror(ret));
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	int optval = 1;
	ret = scion_setsockopt(socket, SOL_SOCKET, SO_BROADCAST, &optval, sizeof(optval));
	if (ret != 0) {
		printf("scion_setsockopt failed: (code %d, '%s')\n", ret, scion_strerror(ret));
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	optval = -2;
	ret = scion_getsockopt(socket, SOL_SOCKET, SO_BROADCAST, &optval, &len);
	if (ret != 0) {
		printf("scion_getsockopt failed: (code %d, '%s')\n", ret, scion_strerror(ret));
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}
	if (optval != 1) {
		printf("socket option value not correct\n");
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	printf("\nDone.\n");
	ret = EXIT_SUCCESS;

cleanup_socket:
	scion_close(socket);

cleanup_network:
	scion_network_free(network);

cleanup_topology:
	scion_topology_free(topology);

	return ret;
}
