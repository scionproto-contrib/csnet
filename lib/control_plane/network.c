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
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "control_plane/network.h"

static int determine_source_addr(struct scion_topology *topology, struct sockaddr_storage *addr, socklen_t *addrlen)
{
	int ret;

	enum scion_addr_family address_family = topology->local_addr_family;
	struct scion_border_router *first_br = topology->border_routers->first->value;

	struct sockaddr_storage first_br_addr;
	socklen_t first_br_addr_len;
	if (address_family == SCION_AF_IPV4) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)&first_br_addr;
		addr_in->sin_family = AF_INET;
		addr_in->sin_port = htons(first_br->port);
		ret = inet_pton(AF_INET, first_br->ip, &addr_in->sin_addr);
		if (ret != 1) {
			return SCION_TOPOLOGY_INVALID;
		}
		first_br_addr_len = sizeof(struct sockaddr_in);
	} else if (address_family == SCION_AF_IPV6) {
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&first_br_addr;
		addr_in6->sin6_family = AF_INET6;
		addr_in6->sin6_port = htons(first_br->port);
		ret = inet_pton(AF_INET6, first_br->ip, &addr_in6->sin6_addr);
		if (ret != 1) {
			return SCION_TOPOLOGY_INVALID;
		}
		first_br_addr_len = sizeof(struct sockaddr_in6);
	} else {
		return SCION_GENERIC_ERR;
	}

	int sock_fd = socket((int)address_family, SOCK_DGRAM, 0);
	if (sock_fd == -1) {
		return SCION_GENERIC_ERR;
	}

	do {
		ret = connect(sock_fd, (struct sockaddr *)&first_br_addr, first_br_addr_len);
	} while (ret == -1 && errno == EINTR);

	if (ret != 0) {
		ret = SCION_GENERIC_ERR;
		goto cleanup_socket;
	}

	ret = getsockname(sock_fd, (struct sockaddr *)addr, addrlen);
	if (ret != 0) {
		ret = SCION_GENERIC_ERR;
	}

cleanup_socket:
	close(sock_fd);

	return ret;
}

int scion_network(struct scion_network **net, struct scion_topology *topology)
{
	assert(net);
	assert(topology);
	int ret;

	struct scion_network *new_net = malloc(sizeof(struct scion_network));
	if (new_net == NULL) {
		return SCION_MEM_ALLOC_FAIL;
	}

	new_net->topology = topology;

	new_net->src_addr_len = sizeof(struct sockaddr_storage);
	ret = determine_source_addr(topology, &new_net->src_addr, &new_net->src_addr_len);
	new_net->src_addr_set = ret == 0;

	*net = new_net;

	return ret;
}

void scion_network_free(struct scion_network *net)
{
	free(net);
}

int scion_network_set_addr(struct scion_network *net, const struct sockaddr *addr, socklen_t addr_len)
{
	assert(net);
	assert(addr);

	if (addr_len > sizeof(net->src_addr)) {
		return SCION_ADDR_INVALID;
	}

	(void)memcpy(&net->src_addr, addr, addr_len);
	net->src_addr_len = addr_len;
	net->src_addr_set = true;

	return 0;
}

int scion_network_get_addr(struct scion_network *net, struct sockaddr *addr, socklen_t *addr_len)
{
	assert(net);
	assert(addr);
	assert(addr_len);

	if (*addr_len < net->src_addr_len) {
		return SCION_ADDR_BUF_ERR;
	}

	(void)memcpy(addr, &net->src_addr, net->src_addr_len);
	*addr_len = net->src_addr_len;

	return 0;
}
