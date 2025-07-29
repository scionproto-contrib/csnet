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
#include <netinet/in.h>
#include <scion/scion.h>
#include <stdio.h>
#include <stdlib.h>

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

	ret = scion_connect(scion_sock, (struct sockaddr *)&dst_addr, sizeof(dst_addr), dst_ia);
	if (ret != 0) {
		printf("ERROR: Socket connect failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	char chunk_1[] = "Hello, Scion! (from Linux) ";
	char chunk_2[] = "Please remember that...";

	struct iovec data[2] = { { .iov_base = chunk_1, .iov_len = sizeof(chunk_1) - 1 },
		{ .iov_base = chunk_2, .iov_len = sizeof(chunk_2) - 1 } };

	struct msghdr msg = {
		.msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = data,
		.msg_iovlen = 2,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0,
	};

	// ### Send and Receive ###
	ret = scion_sendmsg(scion_sock, &msg, /* flags: */ 0, 0, NULL);
	if (ret < 0) {
		printf("ERROR: Send failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}
	printf("[Sent %d bytes]: '%s', '%s'\n", ret, chunk_1, chunk_2);

	char rcv_chunk_1[14] = { 0 };
	char rcv_chunk_2[21] = { 0 };
	char rcv_chunk_3[100] = { 0 };

	struct iovec rcv_data[3] = { { .iov_base = rcv_chunk_1, .iov_len = sizeof(rcv_chunk_1) - 1 },
		{ .iov_base = rcv_chunk_2, .iov_len = sizeof(rcv_chunk_2) - 1 },
		{ .iov_base = rcv_chunk_3, .iov_len = sizeof(rcv_chunk_3) - 1 } };

	struct msghdr rcv_msg = { .msg_name = NULL,
		.msg_namelen = 0,
		.msg_iov = rcv_data,
		.msg_iovlen = 3,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0 };

	ret = scion_recvmsg(scion_sock, &rcv_msg, /* flags: */ 0, NULL, NULL);
	if (ret < 0) {
		printf("ERROR: Receive failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}
	printf("[Received %d bytes]: '%s', '%s', '%s'\n", ret, rcv_chunk_1, rcv_chunk_2, rcv_chunk_3);

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
