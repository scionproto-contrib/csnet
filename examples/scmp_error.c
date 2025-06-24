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

bool received_scmp = false;

static void handle_scmp(uint8_t *buf, size_t size, void *ctx)
{
	uint8_t type = scion_scmp_get_type(buf, size);
	uint8_t code = scion_scmp_get_code(buf, size);

	printf("SCMP error message received (type: %u, code: %u):\n", type, code);

	for (int i = 0; i < size; i++) {
		printf("%02x", buf[i]);
	}
	printf("\n");

	received_scmp = true;
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

	struct sockaddr_in dst_addr;
	dst_addr.sin_addr.s_addr = inet_addr("127.0.0.100");
	dst_addr.sin_family = AF_INET;
	dst_addr.sin_port = htons(31002);
	scion_ia dst_ia = scion_topology_get_local_ia(topology);

	struct scion_socket *scion_sock;
	ret = scion_socket(&scion_sock, SCION_AF_INET, SCION_PROTO_UDP, network);
	if (ret != 0) {
		printf("ERROR: Socket setup failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_network;
	}

	ret = scion_setsockerrcb(scion_sock, handle_scmp, /* ctx: */ NULL);
	if (ret != 0) {
		printf("ERROR: Setting socket SCMP error handler failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	struct timeval timeout = { .tv_sec = 3, .tv_usec = 0 };
	ret = scion_setsockopt(scion_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
	if (ret != 0) {
		printf("ERROR: Setting SO_RCVTIMEO failed with error code: %d\n", ret);
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
	char tx_buf[] = "Hello, Scion! (from Linux)";
	ret = scion_send(scion_sock, tx_buf, sizeof tx_buf - 1, /* flags: */ 0);
	if (ret < 0) {
		printf("ERROR: Send failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	printf("[Sent %d bytes]: \"%s\"\n", ret, tx_buf);

	char rx_buf[200];
	ret = scion_recv(scion_sock, &rx_buf, sizeof rx_buf - 1, /* flags: */ 0);
	if (ret != SCION_WOULD_BLOCK) {
		printf("ERROR: Receive failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	if (received_scmp != true) {
		printf("ERROR: Did not receive SCMP error message: %d\n", ret);
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
