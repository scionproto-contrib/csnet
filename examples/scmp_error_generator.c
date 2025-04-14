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

#include <scion/scion.h>

int main(int argc, char *argv[])
{
	int ret;

	printf("\nHello SCION on Linux\n\n");

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

	struct sockaddr_in src_addr;
	src_addr.sin_addr.s_addr = inet_addr("127.0.0.100");
	src_addr.sin_family = AF_INET;
	src_addr.sin_port = htons(31002);

	while (1) {
		struct scion_socket *scion_sock;
		ret = scion_socket(&scion_sock, SCION_AF_IPV4, SCION_PROTO_UDP, network);
		if (ret != 0) {
			printf("ERROR: Socket setup failed with error code: %d\n", ret);
			ret = EXIT_FAILURE;
			goto cleanup_network;
		}

		ret = scion_bind(scion_sock, (struct sockaddr *)&src_addr, sizeof(src_addr));
		if (ret != 0) {
			printf("ERROR: Socket bind failed with error code: %d\n", ret);
			ret = EXIT_FAILURE;
			goto cleanup_socket;
		}

		struct sockaddr_storage sender_addr;
		socklen_t sender_addr_len = sizeof(sender_addr);
		scion_ia sender_ia;
		char rx_buf[200];

		struct scion_path *path;
		int n = scion_recvfrom(scion_sock, &rx_buf, sizeof rx_buf - 1, /* flags: */ 0, (struct sockaddr *)&sender_addr,
			&sender_addr_len, &sender_ia, &path);
		if (n < 0) {
			printf("ERROR: Receive failed with error code: %d\n", n);
			ret = EXIT_FAILURE;
			goto cleanup_socket;
		}
		rx_buf[n] = '\0';

		scion_close(scion_sock);

		ret = scion_socket(&scion_sock, SCION_AF_IPV4, SCION_PROTO_SCMP, network);
		if (ret != 0) {
			printf("ERROR: SCMP socket setup failed with error code: %d\n", ret);
			ret = EXIT_FAILURE;
			goto cleanup_path;
		}

		ret = scion_bind(scion_sock, (struct sockaddr *)&src_addr, sizeof(src_addr));
		if (ret != 0) {
			printf("ERROR: SCMP socket bind failed with error code: %d\n", ret);
			ret = EXIT_FAILURE;
			goto cleanup_path;
		}

		// Destination Unreachable with Code 4 (Port unreachable)
		uint8_t scmp_data[] = {
			0x01,
			0x04,
			0x00,
			0x00,
		};

		ret = scion_path_reverse(path);
		if (ret != 0) {
			printf("ERROR: Reversing path failed with error code: %d\n", ret);
			ret = EXIT_FAILURE;
			goto cleanup_path;
		}

		ret = scion_sendto(scion_sock, scmp_data, sizeof(scmp_data), /* flags: */ 0, (struct sockaddr *)&sender_addr,
			sender_addr_len, sender_ia, path);
		if (ret < 0) {
			printf("ERROR: Send failed with error code: %d\n", n);
			ret = EXIT_FAILURE;
		}

		printf("Replied with SCMP error\n");
		ret = EXIT_SUCCESS;

cleanup_path:
		scion_path_free(path);

cleanup_socket:
		scion_close(scion_sock);

		if (ret != EXIT_SUCCESS) {
			break;
		}
	}

cleanup_network:
	scion_network_free(network);

cleanup_topology:
	scion_topology_free(topology);

	return ret;
}
