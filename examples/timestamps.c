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
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/errqueue.h>
#endif

#include <scion/scion.h>
#include <scion/scion_timestamp.h>

// A buffer for the control message with the timestamps of the kernel. The union gives it the alignment of a control
// message header, which a plain char array does not guarantee.
union control_buffer {
#ifdef __linux__
	char buf[CMSG_SPACE(sizeof(struct scm_timestamping))];
#else
	// Only Linux has timestamps of the kernel, so there is no control message.
	char buf[CMSG_SPACE(0)];
#endif
	struct cmsghdr align;
};

static const char *level_name(enum scion_timestamp_level level)
{
	switch (level) {
	case SCION_TIMESTAMP_USER:
		return "user space";
	case SCION_TIMESTAMP_KERNEL:
		return "kernel";
	case SCION_TIMESTAMP_HARDWARE:
		return "hardware";
	}

	return "unknown";
}

static void print_timestamp(const char *name, const struct scion_timestamp *timestamp)
{
	printf("%s timestamp: %lld.%09ld s (%s)\n", name, (long long)timestamp->time.tv_sec, timestamp->time.tv_nsec,
		level_name(timestamp->level));
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

	// The program sends a packet to itself, so no server is needed. The packet stays in the local AS.
	struct sockaddr_in addr = { 0 };
	addr.sin_addr.s_addr = inet_addr("127.0.0.100");
	addr.sin_family = AF_INET;
	addr.sin_port = htons(31000);
	scion_ia ia = scion_topology_get_local_ia(topology);

	struct scion_socket *scion_sock;
	ret = scion_socket(&scion_sock, SCION_AF_INET, SCION_SOCK_DGRAM, SCION_PROTO_UDP, network);
	if (ret != 0) {
		printf("ERROR: Socket setup failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_network;
	}

	ret = scion_bind(scion_sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret != 0) {
		printf("ERROR: Socket bind failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	// ### Timestamps ###
	// Hardware timestamps need a network card that supports them and are enabled for its interface. Run the example
	// with the name of the interface, for example "eth0", and with the privilege to administer the network.
	bool is_hardware_enabled = false;
	if (argc > 1) {
		ret = scion_set_hwtimestamping(argv[1], true);
		if (ret == 0) {
			is_hardware_enabled = true;
		} else {
			printf("WARNING: Hardware timestamping of %s failed with error code: %d (%s)\n", argv[1], ret,
				scion_strerror(ret));
		}
	}

	// The kernel timestamps the packets of the socket if it is asked for, on Linux. Otherwise, the timestamps are taken
	// in user space.
	enum scion_timestamp_level level = is_hardware_enabled ? SCION_TIMESTAMP_HARDWARE : SCION_TIMESTAMP_KERNEL;
	ret = scion_timestamp_set_level(scion_sock, level);
	if (ret != 0) {
		printf("WARNING: Timestamping of the socket failed with error code: %d (%s)\n", ret, scion_strerror(ret));
	}

	// The kernel enables the timestamps of received packets in the background when the first socket asks for them.
	// A packet that arrives right away may not have one.
	usleep(50 * 1000);
	printf("Hardware timestamps are %s.\n\n", is_hardware_enabled ? "enabled" : "not enabled");

	// ### Send and Receive ###
	// The kernel timestamps the sent packet on its own, so scion_sendto() is enough. The timestamp is not part of the
	// message.
	char tx_buf[] = "Hello, Scion! (from Linux)";
	ssize_t size = scion_sendto(scion_sock, tx_buf, sizeof(tx_buf) - 1, /* flags: */ 0, (struct sockaddr *)&addr,
		sizeof(addr), ia, /* path: */ NULL);
	if (size < 0) {
		printf("ERROR: Send failed with error code: %zd\n", size);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}
	printf("[Sent %zd bytes]: \"%s\"\n", size, tx_buf);

	// The timestamp of a received packet is returned in the control data of the received message, so the packet is
	// received with scion_recvmsg().
	char rx_buf[200];
	union control_buffer control;
	struct iovec iov = { .iov_base = rx_buf, .iov_len = sizeof(rx_buf) - 1 };
	struct msghdr msg = {
		.msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.buf, .msg_controllen = sizeof(control.buf)
	};
	size = scion_recvmsg(scion_sock, &msg, /* flags: */ 0, /* src_ia: */ NULL, /* path: */ NULL);
	if (size < 0) {
		printf("ERROR: Receive failed with error code: %zd\n", size);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}
	rx_buf[size] = '\0';
	printf("[Received %zd bytes]: \"%s\"\n\n", size, rx_buf);

	// ### Get the timestamps ###
	// The kernel keeps the timestamp of the sent packet on the socket until it is read here.
	// The best timestamp the kernel provided is returned. If it provided none, the level says that the time was taken
	// in user space.
	struct scion_timestamp tx_timestamp;
	ret = scion_timestamp_get_tx(scion_sock, &tx_timestamp, /* timeout_ms: */ 1000);
	if (ret != 0) {
		printf("ERROR: Getting the transmit timestamp failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}
	print_timestamp("Transmit", &tx_timestamp);

	struct scion_timestamp rx_timestamp;
	ret = scion_timestamp_get_rx(scion_sock, &msg, &rx_timestamp);
	if (ret != 0) {
		printf("ERROR: Getting the receive timestamp failed with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}
	print_timestamp("Receive ", &rx_timestamp);

	// Two timestamps can only be compared if they were taken with the same clock. The clock of the hardware is not
	// related to the system time, but its timestamps of the same network card can be compared with each other.
	if (tx_timestamp.level == rx_timestamp.level) {
		double elapsed_us = (double)(rx_timestamp.time.tv_sec - tx_timestamp.time.tv_sec) * 1e6
							+ (double)(rx_timestamp.time.tv_nsec - tx_timestamp.time.tv_nsec) / 1e3;
		printf("\nThe packet took %.1f us (%s timestamps).\n", elapsed_us, level_name(tx_timestamp.level));
	} else {
		printf("\nThe timestamps are of different clocks and cannot be compared.\n");
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
