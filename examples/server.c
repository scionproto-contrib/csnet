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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <scion/scion.h>

int main()
{
	int ret;

	struct scion_socket *scion_sock;
	ret = scion_socket(&scion_sock, SCION_AF_INET, SCION_SOCK_DGRAM, SCION_PROTO_UDP, NULL);
	if (ret != 0) {
		printf("ERROR: Socket setup failed with error code: %d", ret);
		return EXIT_FAILURE;
	}

	struct sockaddr_in src_addr;
	src_addr.sin_family = AF_INET;
	src_addr.sin_addr.s_addr = inet_addr("0.0.0.0");
	src_addr.sin_port = htons(31001);

	ret = scion_bind(scion_sock, (struct sockaddr *)&src_addr, sizeof(src_addr));
	if (ret != 0) {
		printf("ERROR: Failed to bind with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_socket;
	}

	while (1) {
		struct sockaddr_storage sender_addr;
		socklen_t sender_addr_len = sizeof(sender_addr);
		scion_ia sender_ia;

		struct scion_path *path;
		char rx_buf[200];

		int n = scion_recvfrom(scion_sock, &rx_buf, sizeof rx_buf - 1, /* flags: */ 0, (struct sockaddr *)&sender_addr,
			&sender_addr_len, &sender_ia, &path);
		if (n < 0) {
			printf("ERROR: Receive failed with error code: %d\n", n);
			continue;
		}
		rx_buf[n] = '\0';
		printf("[Received %d bytes]: \"%s\"\n", n, rx_buf);

		ret = scion_path_reverse(path);
		if (ret != 0) {
			printf("ERROR: reverse failed with error code: %d\n", n);
			goto cleanup_path;
		}

		ret = scion_sendto(
			scion_sock, rx_buf, n, /* flags: */ 0, (struct sockaddr *)&sender_addr, sender_addr_len, sender_ia, path);
		if (ret < 0) {
			printf("ERROR: Send failed with error code: %d\n", ret);
			goto cleanup_path;
		}
		printf("[Sent %d bytes]: \"%s\"\n", ret, rx_buf);

cleanup_path:
		scion_path_free(path);
	}

cleanup_socket:
	scion_close(scion_sock);

	return ret;
}
