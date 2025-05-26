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
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "common/isd_as.h"
#include "common/path_collection.h"
#include "control_plane/fetch.h"
#include "control_plane/network.h"
#include "control_plane/policy.h"
#include "control_plane/topology.h"
#include "data_plane/packet.h"
#include "data_plane/path.h"
#include "data_plane/scmp.h"
#include "data_plane/socket.h"
#include "data_plane/udp.h"
#include "data_plane/underlay.h"

#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

#ifndef MSG_MORE
#define MSG_MORE 0
#endif

#define IMPLEMENTED_SEND_FLAGS (MSG_CONFIRM | MSG_DONTWAIT | MSG_MORE)
#define IMPLEMENTED_RECV_FLAGS (MSG_DONTWAIT | MSG_PEEK)
#define PATH_EXPIRATION_THRESHOLD_IN_SECONDS 60

static bool sockaddr_eq(enum scion_proto protocol, struct sockaddr *this_addr, struct sockaddr *that_addr)
{
	bool ignore_port = protocol == SCION_PROTO_SCMP;

	if (this_addr->sa_family != that_addr->sa_family) {
		return false;
	}

	if (this_addr->sa_family == AF_INET) {
		struct sockaddr_in *this_addr_in = (struct sockaddr_in *)this_addr;
		struct sockaddr_in *that_addr_in = (struct sockaddr_in *)that_addr;

		return (ignore_port || this_addr_in->sin_port == that_addr_in->sin_port)
			   && (memcmp(&this_addr_in->sin_addr, &that_addr_in->sin_addr, sizeof(this_addr_in->sin_addr)) == 0);
	}

	if (this_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *this_addr_in6 = (struct sockaddr_in6 *)this_addr;
		struct sockaddr_in6 *that_addr_in6 = (struct sockaddr_in6 *)that_addr;

		return (ignore_port || this_addr_in6->sin6_port == that_addr_in6->sin6_port)
			   && (memcmp(&this_addr_in6->sin6_addr, &that_addr_in6->sin6_addr, sizeof(this_addr_in6->sin6_addr)) == 0);
	}

	return false;
}

static bool sockaddr_is_any(struct sockaddr *addr)
{
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *sockaddr_in = (struct sockaddr_in *)addr;
		return sockaddr_in->sin_addr.s_addr == INADDR_ANY;
	}

	if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sockaddr_in6 = (struct sockaddr_in6 *)addr;
		return IN6_IS_ADDR_UNSPECIFIED(&sockaddr_in6->sin6_addr);
	}

	return false;
}

static void sockaddr_copy_port(
	struct sockaddr *dst_addr, socklen_t *dst_addr_len, const struct sockaddr *src_addr, socklen_t src_addr_len)
{
	assert(*dst_addr_len >= src_addr_len);

	*dst_addr_len = src_addr_len;

	if (src_addr->sa_family == AF_INET) {
		struct sockaddr_in *src_addr_in = (struct sockaddr_in *)src_addr;
		struct sockaddr_in *dst_addr_in = (struct sockaddr_in *)dst_addr;
		dst_addr_in->sin_port = src_addr_in->sin_port;
	} else if (src_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *src_addr_in6 = (struct sockaddr_in6 *)src_addr;
		struct sockaddr_in6 *dst_addr_in6 = (struct sockaddr_in6 *)dst_addr;
		dst_addr_in6->sin6_port = src_addr_in6->sin6_port;
	}
}

static void sockaddr_copy_address(
	struct sockaddr *dst_addr, socklen_t *dst_addr_len, const struct sockaddr *src_addr, socklen_t src_addr_len)
{
	assert(*dst_addr_len >= src_addr_len);

	*dst_addr_len = src_addr_len;

	if (src_addr->sa_family == AF_INET) {
		struct sockaddr_in *src_addr_in = (struct sockaddr_in *)src_addr;
		struct sockaddr_in *dst_addr_in = (struct sockaddr_in *)dst_addr;
		dst_addr_in->sin_family = AF_INET;
		dst_addr_in->sin_addr = src_addr_in->sin_addr;
	} else if (src_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *src_addr_in = (struct sockaddr_in6 *)src_addr;
		struct sockaddr_in6 *dst_addr_in = (struct sockaddr_in6 *)dst_addr;
		dst_addr_in->sin6_family = AF_INET6;
		dst_addr_in->sin6_addr = src_addr_in->sin6_addr;
	}
}

static void socket_free(struct scion_socket *scion_sock)
{
	if (scion_sock == NULL) {
		return;
	}
	scion_sock->socket_fd = -1;
	scion_path_collection_free(scion_sock->paths);
	free(scion_sock);
}

static void set_source_address(struct scion_socket *socket, struct sockaddr *addr, socklen_t addr_len, bool with_port)
{
	if (with_port) {
		socket->src_addr_len = sizeof(socket->src_addr);
		sockaddr_copy_port((struct sockaddr *)&socket->src_addr, &socket->src_addr_len, addr, addr_len);
	}

	// Only set the address if it is not the wildcard address
	if (!sockaddr_is_any(addr)) {
		socket->src_addr_len = sizeof(socket->src_addr);
		sockaddr_copy_address((struct sockaddr *)&socket->src_addr, &socket->src_addr_len, addr, addr_len);

		socket->is_src_addr_set = true;
	}
}

static int get_source_address(struct scion_socket *socket, struct sockaddr *addr, socklen_t *addr_len)
{
	if (!socket->is_src_addr_set) {
		return SCION_SRC_ADDR_UNKNOWN;
	}

	sockaddr_copy_address(addr, addr_len, (struct sockaddr *)&socket->src_addr, socket->src_addr_len);
	sockaddr_copy_port(addr, addr_len, (struct sockaddr *)&socket->src_addr, socket->src_addr_len);
	return 0;
}

static bool is_source_address_set(struct scion_socket *socket)
{
	return socket->is_src_addr_set;
}

static int bind_if_unbound(struct scion_socket *scion_sock)
{
	assert(scion_sock);
	int ret;

	if (scion_sock->is_bound) {
		return 0;
	}

	if (scion_sock->network == NULL) {
		return SCION_NETWORK_UNKNOWN;
	}

	struct sockaddr_storage addr;
	socklen_t addr_len;

	if (scion_sock->local_addr_family == SCION_AF_IPV4) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
		addr_in->sin_family = AF_INET;
		addr_in->sin_addr.s_addr = htonl(INADDR_ANY);
		addr_in->sin_port = htons(0);
		addr_len = sizeof(struct sockaddr_in);
	} else {
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr;
		addr_in6->sin6_family = AF_INET6;
		addr_in6->sin6_addr = in6addr_any;
		addr_in6->sin6_port = htons(0);
		addr_len = sizeof(struct sockaddr_in6);
	}

	ret = scion_bind(scion_sock, (struct sockaddr *)&addr, addr_len);
	if (ret != 0) {
		return ret;
	}

	return 0;
}

static int fetch_paths(struct scion_socket *scion_sock, scion_ia dst_ia, struct scion_path_collection **paths)
{
	assert(scion_sock);
	assert(scion_sock->network);
	assert(paths);
	int ret;

	ret = scion_fetch_paths(scion_sock->network, dst_ia, scion_sock->debug ? SCION_FETCH_OPT_DEBUG : 0, paths);
	if (ret != 0) {
		return ret;
	}

	return ret;
}

int scion_socket(struct scion_socket **scion_sock, enum scion_addr_family addr_family, enum scion_proto protocol,
	struct scion_network *network)
{
	assert(scion_sock);
	int ret;

	struct scion_socket *scion_sock_storage = calloc(1, sizeof(struct scion_socket));

	if (scion_sock_storage == NULL) {
		return SCION_MEM_ALLOC_FAIL;
	}

	scion_sock_storage->network = network;

	if (network && network->topology->local_addr_family != addr_family) {
		ret = SCION_NETWORK_ADDR_FAMILY_MISMATCH;
		goto cleanup_socket_storage;
	}

	if (addr_family != SCION_AF_IPV4 && addr_family != SCION_AF_IPV6) {
		ret = SCION_ADDR_FAMILY_UNKNOWN;
		goto cleanup_socket_storage;
	}
	scion_sock_storage->local_addr_family = addr_family;

	if (protocol != SCION_PROTO_UDP && protocol != SCION_PROTO_SCMP) {
		ret = SCION_PROTO_UNKNOWN;
		goto cleanup_socket_storage;
	}
	scion_sock_storage->protocol = protocol;

	scion_sock_storage->socket_fd = socket((int)addr_family, SOCK_DGRAM, 0);

	if (scion_sock_storage->socket_fd == -1) {
		(void)fprintf(stderr, "ERROR: encountered an unexpected error when creating the socket (%s, code %d)\n",
			strerror(errno), errno);
		ret = SCION_GENERIC_ERR;
		goto cleanup_socket_storage;
	}

	scion_sock_storage->paths = NULL;
	scion_sock_storage->policy = scion_policy_least_hops;

	scion_sock_storage->src_addr_len = sizeof(scion_sock_storage->src_addr);

	if (network != NULL) {
		struct scion_underlay probe_underlay;

		// get arbitrary border router
		ret = scion_topology_next_underlay_hop(network->topology, SCION_INTERFACE_ANY, &probe_underlay);
		if (ret != 0) {
			return ret;
		}

		struct sockaddr_storage src_addr;
		socklen_t src_addr_len = sizeof(src_addr);
		// determine the source address by connecting to the border router
		ret = scion_underlay_probe(&probe_underlay, (struct sockaddr *)&src_addr, &src_addr_len);
		if (ret != 0) {
			return ret;
		}

		set_source_address(scion_sock_storage, (struct sockaddr *)&src_addr, src_addr_len, /* with_port */ false);
	}

	*scion_sock = scion_sock_storage;

	return 0;

cleanup_socket_storage:
	free(scion_sock_storage);

	return ret;
}

static int refresh_connected_paths(struct scion_socket *scion_sock)
{
	scion_path_collection_free(scion_sock->paths);

	int ret = fetch_paths(scion_sock, scion_sock->dst_ia, &scion_sock->paths);
	if (ret != 0) {
		return ret;
	}

	scion_sock->policy.fn(scion_sock->paths, scion_sock->policy.ctx);

	if (scion_path_collection_size(scion_sock->paths) == 0) {
		return SCION_NO_PATHS;
	}

	if (scion_path_collection_first(scion_sock->paths)->path_type == SCION_PATH_TYPE_EMPTY
		&& scion_sock->dst_addr.ss_family != scion_sock->local_addr_family) {
		return SCION_ADDR_FAMILY_MISMATCH;
	}

	return 0;
}

int scion_connect(struct scion_socket *scion_sock, const struct sockaddr *addr, socklen_t addrlen, scion_ia ia)
{
	assert(scion_sock);
	assert(addr);
	int ret;

	if (scion_sock->network == NULL) {
		return SCION_NETWORK_UNKNOWN;
	}

	ret = bind_if_unbound(scion_sock);
	if (ret != 0) {
		return ret;
	}

	(void)memcpy(&scion_sock->dst_addr, addr, addrlen);
	scion_sock->dst_addr_len = addrlen;
	scion_sock->dst_ia = ia;

	ret = refresh_connected_paths(scion_sock);
	if (ret != 0) {
		return ret;
	}

	scion_sock->is_connected = true;

	return 0;
}

static ssize_t scion_sendto_path(struct scion_socket *scion_sock, const void *buf, size_t size, int flags,
	const struct sockaddr *dst_addr, socklen_t dst_addr_len, struct scion_path *path)
{
	assert(scion_sock->protocol == SCION_PROTO_UDP || scion_sock->protocol == SCION_PROTO_SCMP);
	assert(path);
	ssize_t ret;

	if (path->metadata != NULL && path->metadata->expiry <= time(NULL) + PATH_EXPIRATION_THRESHOLD_IN_SECONDS) {
		return SCION_PATH_EXPIRED;
	}

	// Create SCION Packet
	struct scion_packet packet = { 0 };
	packet.version = 0;
	packet.traffic_class = 0;
	packet.flow_id = 1;
	packet.next_hdr = (uint8_t)scion_sock->protocol;
	packet.dst_ia = path->dst;
	packet.src_ia = path->src;
	packet.path = path;
	packet.path_type = (uint8_t)path->path_type;

	// Destination
	if (dst_addr->sa_family == AF_INET) {
		// IPv4
		packet.dst_addr_type = SCION_ADDR_TYPE_T4IP;
		packet.raw_dst_addr_length = 4;
		packet.raw_dst_addr = (uint8_t *)malloc(packet.raw_dst_addr_length);
		struct sockaddr_in *dst_sockaddr = (struct sockaddr_in *)dst_addr;
		(void)memcpy(packet.raw_dst_addr, &(dst_sockaddr->sin_addr.s_addr), packet.raw_dst_addr_length);
	} else if (dst_addr->sa_family == AF_INET6) {
		// IPv6
		packet.dst_addr_type = SCION_ADDR_TYPE_T16IP;
		packet.raw_dst_addr_length = 16;
		packet.raw_dst_addr = (uint8_t *)malloc(packet.raw_dst_addr_length);
		struct sockaddr_in6 *dst_sockaddr = (struct sockaddr_in6 *)dst_addr;
		(void)memcpy(packet.raw_dst_addr, dst_sockaddr->sin6_addr.s6_addr, packet.raw_dst_addr_length);
	} else {
		// Unsupported destination address type
		ret = SCION_ADDR_FAMILY_UNKNOWN;
		goto cleanup_packet;
	}

	// Source
	struct sockaddr_storage src_addr;
	socklen_t src_addr_len = sizeof(src_addr);

	ret = get_source_address(scion_sock, (struct sockaddr *)&src_addr, &src_addr_len);
	if (ret != 0) {
		goto cleanup_packet;
	}

	if (scion_sock->src_addr.ss_family == AF_INET) {
		// IPv4
		packet.src_addr_type = SCION_ADDR_TYPE_T4IP;
		packet.raw_src_addr_length = 4;
		packet.raw_src_addr = (uint8_t *)malloc(packet.raw_src_addr_length);
		struct sockaddr_in *src_sockaddr = (struct sockaddr_in *)&scion_sock->src_addr;
		(void)memcpy(packet.raw_src_addr, &(src_sockaddr->sin_addr.s_addr), packet.raw_src_addr_length);
	} else if (scion_sock->src_addr.ss_family == AF_INET6) {
		// IPv6
		packet.src_addr_type = SCION_ADDR_TYPE_T16IP;
		packet.raw_src_addr_length = 16;
		packet.raw_src_addr = (uint8_t *)malloc(packet.raw_src_addr_length);
		struct sockaddr_in6 *src_sockaddr = (struct sockaddr_in6 *)&scion_sock->src_addr;
		(void)memcpy(packet.raw_src_addr, src_sockaddr->sin6_addr.s6_addr, packet.raw_src_addr_length);
	} else {
		// Unsupported source address type
		ret = SCION_ADDR_FAMILY_UNKNOWN;
		goto cleanup_packet;
	}

	// Create payload, depending on the protocol.
	if (scion_sock->protocol == SCION_PROTO_UDP) {
		// Create UDP packet
		struct scion_udp udp_packet = { 0 };
		if (size > UINT16_MAX) {
			ret = SCION_MSG_TOO_LARGE;
			goto cleanup_packet;
		}
		udp_packet.data_length = (uint16_t)size;

		if (size > 0) {
			udp_packet.data = (uint8_t *)malloc(size);
			(void)memcpy(udp_packet.data, buf, size);
		} else {
			udp_packet.data = NULL;
		}

		// Set Ports
		if (dst_addr->sa_family == AF_INET) {
			// IPv4
			udp_packet.dst_port = ntohs(((struct sockaddr_in *)dst_addr)->sin_port);
		} else if (dst_addr->sa_family == AF_INET6) {
			// IPv6
			udp_packet.dst_port = ntohs(((struct sockaddr_in6 *)dst_addr)->sin6_port);
		}
		if (scion_sock->src_addr.ss_family == AF_INET) {
			// IPv4
			udp_packet.src_port = ntohs(((struct sockaddr_in *)&scion_sock->src_addr)->sin_port);
		} else if (scion_sock->src_addr.ss_family == AF_INET6) {
			// IPv6
			udp_packet.src_port = ntohs(((struct sockaddr_in6 *)&scion_sock->src_addr)->sin6_port);
		}

		// Serialize UDP packet into payload buffer of SCION packet
		packet.payload_len = scion_udp_len(&udp_packet);
		packet.payload = (uint8_t *)malloc(packet.payload_len);
		ret = scion_udp_serialize(&udp_packet, packet.payload, &packet.payload_len);
		if (ret != 0) {
			scion_udp_free_internal(&udp_packet);
			goto cleanup_packet;
		}

		scion_udp_free_internal(&udp_packet);

	} else if (scion_sock->protocol == SCION_PROTO_SCMP) {
		if (size > UINT16_MAX) {
			ret = SCION_MSG_TOO_LARGE;
			goto cleanup_packet;
		}
		packet.payload_len = (uint16_t)size;

		if (size > 0) {
			packet.payload = (uint8_t *)malloc(packet.payload_len);
			(void)memcpy(packet.payload, buf, size);
		} else {
			packet.payload = NULL;
		}
	}

	size_t packet_length = scion_packet_len(&packet);
	uint8_t *packet_buf = malloc(packet_length);
	if (packet_buf == NULL) {
		ret = SCION_MEM_ALLOC_FAIL;
		goto cleanup_packet;
	}

	ret = scion_packet_serialize(&packet, packet_buf, &packet_length);
	if (ret != 0) {
		goto cleanup_packet_buf;
	}

	const struct sockaddr *next_hop_addr;
	socklen_t next_hop_addr_length;
	if (path->path_type == SCION_PATH_TYPE_SCION) {
		next_hop_addr = (const struct sockaddr *)&path->underlay_next_hop.addr;
		next_hop_addr_length = path->underlay_next_hop.addrlen;
	} else if (path->path_type == SCION_PATH_TYPE_EMPTY) {
		next_hop_addr = dst_addr;
		next_hop_addr_length = dst_addr_len;
	} else {
		ret = SCION_PATH_TYPE_INVALID;
		goto cleanup_packet_buf;
	}

	if (next_hop_addr->sa_family != scion_sock->local_addr_family) {
		ret = SCION_ADDR_FAMILY_MISMATCH;
		goto cleanup_packet_buf;
	}

	do {
		ret = sendto(scion_sock->socket_fd, packet_buf, packet_length, flags, next_hop_addr, next_hop_addr_length);
	} while (ret == -1 && errno == EINTR);

	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = SCION_WOULD_BLOCK;
		} else if (errno == EACCES) {
			ret = SCION_ADDR_INVALID;
		} else if (errno == EOPNOTSUPP) {
			ret = SCION_FLAG_NOT_SUPPORTED;
		} else if (errno == ENOMEM) {
			ret = SCION_MEM_ALLOC_FAIL;
		} else if (errno == ENOBUFS) {
			ret = SCION_OUTPUT_QUEUE_FULL;
		} else {
			(void)fprintf(stderr, "ERROR: encountered an unexpected error when sending packets (%s, code %d)\n",
				strerror(errno), errno);
			ret = SCION_SEND_ERR;
		}

		goto cleanup_packet_buf;
	}

	if (ret > 0) {
		if (scion_sock->debug) {
			(void)printf("Sending packet over the following path:\n");
			scion_path_print(path);
			(void)printf("\n");
		}

		if ((size_t)ret != packet_length) {
			// Packet partially transmitted
			ret = SCION_SEND_ERR;
		} else {
			ret = (ssize_t)size;
		}
	}

cleanup_packet_buf:
	free(packet_buf);

cleanup_packet:
	packet.path = NULL; // To avoid free'ing socket->path
	scion_packet_free_internal(&packet);

	return ret;
}

static ssize_t scion_sendto_connected_path(struct scion_socket *scion_sock, const void *buf, size_t size, int flags,
	const struct sockaddr *dst_addr, socklen_t dst_addr_len)
{
	struct scion_path *path = scion_path_collection_first(scion_sock->paths);
	if (path == NULL) {
		return SCION_NO_PATHS;
	}

	ssize_t ret = scion_sendto_path(scion_sock, buf, size, flags, dst_addr, dst_addr_len, path);

	if (ret == SCION_PATH_EXPIRED) {
		ret = refresh_connected_paths(scion_sock);
		if (ret != 0) {
			return ret;
		}

		path = scion_path_collection_first(scion_sock->paths);
		if (path == NULL) {
			return SCION_NO_PATHS;
		}

		ret = scion_sendto_path(scion_sock, buf, size, flags, dst_addr, dst_addr_len, path);
	}

	return ret;
}

// TODO: Check Ipv4 Encapsulated in IPv6
ssize_t scion_send(struct scion_socket *scion_sock, const void *buf, size_t size, int flags)
{
	if (scion_sock->network == NULL) {
		return SCION_NETWORK_UNKNOWN;
	}

	return scion_sendto(scion_sock, buf, size, flags, NULL, 0, 0, NULL);
}

// TODO: Check Ipv4 Encapsulated in IPv6
ssize_t scion_sendto(struct scion_socket *scion_sock, const void *buf, size_t size, int flags,
	const struct sockaddr *dst_addr, socklen_t addrlen, scion_ia dst_ia, struct scion_path *path)
{
	assert(scion_sock);
	assert(size == 0 || buf);
	ssize_t ret;

	if (path == NULL && scion_sock->network == NULL) {
		return SCION_NETWORK_UNKNOWN;
	}

	if ((flags & IMPLEMENTED_SEND_FLAGS) != flags) {
		return SCION_FLAG_NOT_IMPLEMENTED;
	}

	ret = bind_if_unbound(scion_sock);
	if (ret != 0) {
		return ret;
	}

	if (dst_addr == NULL) {
		if (!scion_sock->is_connected) {
			return SCION_NOT_CONNECTED;
		}

		dst_addr = (struct sockaddr *)&scion_sock->dst_addr;
		addrlen = scion_sock->dst_addr_len;
		dst_ia = scion_sock->dst_ia;
	}

	if (path != NULL && path->dst != dst_ia) {
		return SCION_DST_MISMATCH;
	}

	// Handle path, there are 3 different cases:
	// 1. No path was provided but destination IA matches the connected IA
	//    --> Use connected path
	// 2. No path was provided and destination IA does not match the connected IA
	//    --> Fetch a temporary path, need to take care of freeing.
	// 3. A path was provided as an argument
	//    --> Use the provided path
	bool cleanup_path = false;
	if (path == NULL) {
		if (scion_sock->is_connected && scion_sock->dst_ia == dst_ia) {
			return scion_sendto_connected_path(scion_sock, buf, size, flags, dst_addr, addrlen);
		}

		struct scion_path_collection *paths;

		ret = fetch_paths(scion_sock, dst_ia, &paths);
		if (ret != 0) {
			return ret;
		}

		path = scion_path_collection_pop(paths);
		if (path == NULL) {
			return SCION_NO_PATHS;
		}

		scion_path_collection_free(paths);
		cleanup_path = true;
	}

	ret = scion_sendto_path(scion_sock, buf, size, flags, dst_addr, addrlen, path);

	if (cleanup_path) {
		scion_path_free(path);
	}

	return ret;
}

ssize_t scion_recv(struct scion_socket *scion_sock, void *buf, size_t size, int flags)
{
	return scion_recvfrom(scion_sock, buf, size, flags, NULL, NULL, NULL, NULL);
}

ssize_t scion_recvfrom(struct scion_socket *scion_sock, void *buf, size_t size, int flags, struct sockaddr *src_addr,
	socklen_t *addrlen, scion_ia *src_ia, struct scion_path **path)
{
	ssize_t ret;
	uint16_t recv_len = 0;

	assert(scion_sock);
	assert(buf);

	if ((flags & IMPLEMENTED_RECV_FLAGS) != flags) {
		return SCION_FLAG_NOT_IMPLEMENTED;
	}

	bool received_anticipated_packet = false;
	while (!received_anticipated_packet) {
		uint8_t packet_buf[size + SCION_MAX_HDR_LEN];
		struct sockaddr_storage sender_addr;
		socklen_t sender_addr_len;

		struct sockaddr_storage underlay_addr;
		socklen_t underlay_addr_len = sizeof(underlay_addr);

		do {
			ret = recvfrom(scion_sock->socket_fd, packet_buf, sizeof(packet_buf), flags,
				(struct sockaddr *)&underlay_addr, &underlay_addr_len);
		} while (ret == -1 && errno == EINTR);

		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				ret = SCION_WOULD_BLOCK;
			} else {
				(void)fprintf(stderr, "ERROR: encountered an unexpected error when receiving packets (%s, code %d)\n",
					strerror(errno), errno);
				ret = SCION_RECV_ERR;
			}

			return ret;
		}

		struct scion_packet packet = { 0 };
		ret = scion_packet_deserialize((uint8_t *)&packet_buf, (size_t)ret, &packet);
		if (ret != 0) {
			// Ignore packet
			continue;
		}
		packet.path->underlay_next_hop = (struct scion_underlay){
			.addr = underlay_addr, .addrlen = underlay_addr_len, .addr_family = scion_sock->local_addr_family
		};

		uint16_t src_port;

		// Deserialize packet
		if (packet.next_hdr == 17) {
			struct scion_udp udp = { 0 };
			ret = scion_udp_deserialize(packet.payload, packet.payload_len, &udp);
			if (ret != 0) {
				// Ignore packet
				ret = 0;
				goto cleanup_packet;
			}

			src_port = udp.src_port;
			recv_len = udp.data_length;
			(void)memcpy(buf, udp.data, recv_len);

			scion_udp_free_internal(&udp);
		} else if (packet.next_hdr == 202) {
			// SCMP message
			src_port = 0; // No port on SCMP
			recv_len = packet.payload_len;
			(void)memcpy(buf, packet.payload, recv_len);
		} else {
			// Ignore packet
			goto cleanup_packet;
		}

		// Determine sender address
		if (packet.raw_src_addr_length == 4) {
			sender_addr_len = sizeof(struct sockaddr_in);

			struct sockaddr_in *sender_addr_in = (struct sockaddr_in *)&sender_addr;
			sender_addr_in->sin_family = AF_INET;
			(void)memcpy(&sender_addr_in->sin_addr.s_addr, packet.raw_src_addr, packet.raw_src_addr_length);
			sender_addr_in->sin_port = htons(src_port);
		} else if (packet.raw_src_addr_length == 16) {
			sender_addr_len = sizeof(struct sockaddr_in6);

			struct sockaddr_in6 *src_addr_in6 = (struct sockaddr_in6 *)&sender_addr;
			src_addr_in6->sin6_family = AF_INET6;
			(void)memcpy(&src_addr_in6->sin6_addr.s6_addr, packet.raw_src_addr, packet.raw_src_addr_length);
			src_addr_in6->sin6_port = htons(src_port);
		} else {
			// Ignore packet
			goto cleanup_packet;
		}

		// SCMP error received
		if (packet.next_hdr == SCION_PROTO_SCMP && scion_scmp_is_error(buf, recv_len)) {
			// Trigger SCMP error callback
			if (scion_sock->scmp_error_cb != NULL) {
				scion_sock->scmp_error_cb(buf, recv_len, scion_sock->scmp_error_ctx);
			}

			// Ignore packet
			goto cleanup_packet;
		}

		// Packet has unexpected protocol
		if (packet.next_hdr != scion_sock->protocol) {
			// Ignore packet
			goto cleanup_packet;
		}

		// Socket is connected, but packet does not come from connected destination
		if (scion_sock->is_connected
			&& !sockaddr_eq(
				scion_sock->protocol, (struct sockaddr *)&scion_sock->dst_addr, (struct sockaddr *)&sender_addr)) {
			// Ignore packet
			goto cleanup_packet;
		}

		// All criteria are met, so we can return the packet
		received_anticipated_packet = true;

		// Set source address of socket to destination address of packet if not known yet
		if (!is_source_address_set(scion_sock)) {
			if (packet.dst_addr_type == SCION_ADDR_TYPE_T4IP) {
				struct sockaddr_in sockaddr_in;
				sockaddr_in.sin_family = AF_INET;
				(void)memcpy(&sockaddr_in.sin_addr.s_addr, packet.raw_dst_addr, packet.raw_dst_addr_length);

				set_source_address(
					scion_sock, (struct sockaddr *)&sockaddr_in, sizeof(sockaddr_in), /* with_port*/ false);
			} else if (packet.dst_addr_type == SCION_ADDR_TYPE_T16IP) {
				struct sockaddr_in6 sockaddr_in6;
				sockaddr_in6.sin6_family = AF_INET6;
				(void)memcpy(&sockaddr_in6.sin6_addr.s6_addr, packet.raw_dst_addr, packet.raw_dst_addr_length);

				set_source_address(
					scion_sock, (struct sockaddr *)&sockaddr_in6, sizeof(sockaddr_in6), /* with_port*/ false);
			}
		}

		if (src_addr != NULL) {
			assert(addrlen);

			if (*addrlen < sender_addr_len) {
				ret = SCION_ADDR_BUF_ERR;
				goto cleanup_packet;
			}

			*addrlen = sender_addr_len;
			(void)memcpy(src_addr, &sender_addr, sender_addr_len);
		}

		if (src_ia != NULL) {
			*src_ia = packet.src_ia;
		}

		if (path != NULL) {
			*path = packet.path;
			packet.path = NULL; // prevent path from being freed by scion_packet_free_internal
		}

cleanup_packet:
		scion_packet_free_internal(&packet);

		// Return on error
		if (ret < 0) {
			return ret;
		}
	}

	return (ssize_t)recv_len;
}

int scion_getsockopt(struct scion_socket *scion_sock, int level, int optname, void *optval, socklen_t *optlen)
{
	assert(scion_sock);
	assert(optval);
	assert(optlen);
	int ret = 0;

	if (level == SOL_SOCKET && optname == SCION_SO_DEBUG) {
		if (*optlen < sizeof(bool)) {
			return SCION_BUFFER_SIZE_ERR;
		}

		*(bool *)optval = scion_sock->debug;
	} else {
		ret = getsockopt(scion_sock->socket_fd, level, optname, optval, optlen);
		if (ret == -1) {
			if (errno == EFAULT) {
				ret = SCION_BUFFER_SIZE_ERR;
			} else if (errno == EINVAL || errno == ENOPROTOOPT) {
				ret = SCION_SOCK_OPT_INVALID;
			} else {
				(void)fprintf(stderr,
					"ERROR: encountered an unexpected error when getting socket option (%s, code %d)\n",
					strerror(errno), errno);
				ret = SCION_GENERIC_ERR;
			}
		}
	}

	return ret;
}

int scion_setsockopt(struct scion_socket *scion_sock, int level, int optname, const void *optval, socklen_t optlen)
{
	assert(scion_sock);
	assert(optval);
	int ret = 0;

	if (level == SOL_SOCKET && optname == SCION_SO_DEBUG) {
		scion_sock->debug = *(bool *)optval;
	} else {
		ret = setsockopt(scion_sock->socket_fd, level, optname, optval, optlen);
		if (ret == -1) {
			if (errno == EFAULT) {
				ret = SCION_BUFFER_SIZE_ERR;
			} else if (errno == EINVAL || errno == ENOPROTOOPT) {
				ret = SCION_SOCK_OPT_INVALID;
			} else {
				(void)fprintf(stderr,
					"ERROR: encountered an unexpected error when setting socket option (%s, code %d)\n",
					strerror(errno), errno);
				ret = SCION_GENERIC_ERR;
			}
		}
	}

	return ret;
}

int scion_bind(struct scion_socket *scion_sock, const struct sockaddr *addr, socklen_t addrlen)
{
	assert(scion_sock);
	assert(addr);
	int ret;

	if (scion_sock->is_bound) {
		return SCION_ALREADY_BOUND;
	}

	if (!(addr->sa_family == SCION_AF_IPV4 || addr->sa_family == SCION_AF_IPV6)) {
		return SCION_ADDR_FAMILY_UNKNOWN;
	}

	if (addr->sa_family != scion_sock->local_addr_family) {
		return SCION_ADDR_FAMILY_MISMATCH;
	}

	ret = bind(scion_sock->socket_fd, addr, addrlen);
	if (ret != 0) {
		if (errno == EADDRINUSE) {
			return SCION_ADDR_IN_USE;
		}

		if (errno == EADDRNOTAVAIL) {
			return SCION_ADDR_NOT_AVAILABLE;
		}

		(void)fprintf(stderr, "ERROR: encountered an unexpected error when binding (code: %d)\n", errno);
		return SCION_GENERIC_ERR;
	}

	struct sockaddr_storage src_addr;
	socklen_t src_addr_len = sizeof(src_addr);

	ret = getsockname(scion_sock->socket_fd, (struct sockaddr *)&src_addr, &src_addr_len);
	if (ret != 0) {
		(void)fprintf(stderr, "ERROR: encountered an unexpected error after binding (code: %d)\n", errno);
		return SCION_GENERIC_ERR;
	}

	set_source_address(scion_sock, (struct sockaddr *)&src_addr, src_addr_len, /* with_port */ true);

	scion_sock->is_bound = true;

	return 0;
}

int scion_close(struct scion_socket *scion_sock)
{
	assert(scion_sock);

	// We can ignore errors here because the file descriptor is closed for sure
	(void)close(scion_sock->socket_fd);
	scion_sock->socket_fd = -1;

	socket_free(scion_sock);

	return 0;
}

int scion_getsockname(struct scion_socket *scion_sock, struct sockaddr *addr, socklen_t *addrlen, scion_ia *ia)
{
	assert(scion_sock);

	if (!scion_sock->is_bound) {
		return SCION_NOT_BOUND;
	}

	if (addr != NULL) {
		assert(addrlen);

		struct sockaddr_storage src_addr;
		socklen_t src_addr_len = sizeof(src_addr);

		int ret = get_source_address(scion_sock, (struct sockaddr *)&src_addr, &src_addr_len);
		if (ret != 0) {
			return ret;
		}

		if (*addrlen < src_addr_len) {
			return SCION_ADDR_BUF_ERR;
		}

		(void)memcpy(addr, &src_addr, src_addr_len);
	}

	if (ia != NULL) {
		if (scion_sock->network == NULL) {
			return SCION_NETWORK_UNKNOWN;
		}

		*ia = scion_sock->network->topology->ia;
	}

	return 0;
}

int scion_getsockfd(struct scion_socket *scion_sock, int *fd)
{
	assert(scion_sock);
	assert(fd);

	*fd = scion_sock->socket_fd;

	return 0;
}

int scion_setsockerrcb(struct scion_socket *scion_sock, scion_socket_scmp_error_cb cb, void *ctx)
{
	assert(scion_sock);

	scion_sock->scmp_error_cb = cb;
	scion_sock->scmp_error_ctx = ctx;

	return 0;
}

int scion_setsockpolicy(struct scion_socket *scion_sock, struct scion_policy policy)
{
	assert(scion_socket);
	int ret = 0;

	scion_sock->policy = policy;

	if (scion_sock->is_connected) {
		ret = refresh_connected_paths(scion_sock);
	}

	return ret;
};

void scion_print_addr(const struct sockaddr *addr, scion_ia ia)
{
	if (addr == NULL) {
		return;
	}

	scion_ia_print(ia);
	(void)printf(",");

	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *raw_addr = (struct sockaddr_in *)addr;
		char *ip_str = inet_ntoa(raw_addr->sin_addr);
		(void)printf("%s:%d", ip_str, ntohs(raw_addr->sin_port));
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *raw_addr = (struct sockaddr_in6 *)addr;
		char ip_str[INET6_ADDRSTRLEN];
		(void)inet_ntop(AF_INET6, &raw_addr->sin6_addr, ip_str, INET6_ADDRSTRLEN);
		(void)printf("%s:%d", ip_str, ntohs(raw_addr->sin6_port));
	} else {
		(void)printf("UNKNOWN ADDR TYPE");
	}
}
