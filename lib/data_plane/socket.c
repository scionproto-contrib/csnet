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
#include "control_plane/network.h"
#include "control_plane/topology.h"
#include "data_plane/packet.h"
#include "data_plane/path.h"
#include "data_plane/scmp.h"
#include "data_plane/selector.h"
#include "data_plane/socket.h"
#include "data_plane/timestamp.h"
#include "data_plane/udp.h"
#include "data_plane/underlay.h"
#include "scion/scion_path.h"
#include "scion/scion_policy.h"
#include "scion/scion_selector.h"

#ifndef MSG_CONFIRM
#define MSG_CONFIRM 0
#endif

#ifndef MSG_MORE
#define MSG_MORE 0
#endif

#define IMPLEMENTED_SEND_FLAGS (MSG_CONFIRM | MSG_DONTWAIT | MSG_MORE)
#ifdef MSG_ERRQUEUE
#define IMPLEMENTED_RECV_FLAGS (MSG_DONTWAIT | MSG_PEEK | MSG_ERRQUEUE)
#else
#define IMPLEMENTED_RECV_FLAGS (MSG_DONTWAIT | MSG_PEEK)
#endif
#define PATH_EXPIRATION_THRESHOLD_IN_SECONDS 60

#define SOCK_TYPE_MASK 0xF

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
	scion_path_cache_clear(&scion_sock->path_cache);
	scion_timestamp_state_free(scion_sock->timestamps);
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

static int get_source_address(const struct scion_socket *socket, struct sockaddr *addr, socklen_t *addr_len)
{
	if (!socket->is_src_addr_set) {
		return SCION_ERR_SRC_ADDR_UNKNOWN;
	}

	sockaddr_copy_address(addr, addr_len, (const struct sockaddr *)&socket->src_addr, socket->src_addr_len);
	sockaddr_copy_port(addr, addr_len, (const struct sockaddr *)&socket->src_addr, socket->src_addr_len);
	return 0;
}

static bool is_source_address_set(const struct scion_socket *socket)
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
		return SCION_ERR_NETWORK_UNKNOWN;
	}

	struct sockaddr_storage addr;
	socklen_t addr_len;

	if (scion_sock->local_addr_family == SCION_AF_INET) {
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

	ret = scion_path_collection_fetch(
		scion_sock->network, dst_ia, scion_sock->debug ? SCION_FETCH_OPT_DEBUG : 0, paths);
	if (ret != 0) {
		return ret;
	}

	scion_sock->policy.fn(*paths, scion_sock->policy.ctx);

	return ret;
}

int scion_socket(struct scion_socket **scion_sock, enum scion_addr_family addr_family, int type,
	enum scion_proto protocol, const struct scion_network *network)
{
	assert(scion_sock);
	int ret;

	struct scion_socket *scion_sock_storage = calloc(1, sizeof(struct scion_socket));

	if (scion_sock_storage == NULL) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}

	scion_sock_storage->timestamps = scion_timestamp_state_create();
	if (scion_sock_storage->timestamps == NULL) {
		ret = SCION_ERR_MEM_ALLOC_FAIL;
		goto cleanup_socket_storage;
	}

	scion_sock_storage->network = network;

	if (network && network->topology->local_addr_family != addr_family) {
		ret = SCION_ERR_NETWORK_ADDR_FAMILY_MISMATCH;
		goto cleanup_socket_storage;
	}

	if (addr_family != SCION_AF_INET && addr_family != SCION_AF_INET6) {
		ret = SCION_ERR_ADDR_FAMILY_UNKNOWN;
		goto cleanup_socket_storage;
	}
	scion_sock_storage->local_addr_family = addr_family;

	// Get rid of the flags
	int socket_type = type & SOCK_TYPE_MASK;

	if (socket_type == SCION_SOCK_DGRAM) {
		// DGRAM sockets must have protocol UDP
		if (protocol != SCION_PROTO_UDP) {
			ret = SCION_ERR_PROTO_INCOMPATIBLE;
			goto cleanup_socket_storage;
		}
	} else if (socket_type == SCION_SOCK_RAW) {
		// Any protocol is allowed
	} else {
		ret = SCION_ERR_SOCK_TYPE_UNKNOWN;
		goto cleanup_socket_storage;
	}

	scion_sock_storage->type = type;
	// Add original flags to datagram socket
	int underlying_socket_type = SOCK_DGRAM | (type & ~SOCK_TYPE_MASK);

	if (protocol != SCION_PROTO_UDP && protocol != SCION_PROTO_SCMP) {
		ret = SCION_ERR_PROTO_UNKNOWN;
		goto cleanup_socket_storage;
	}
	scion_sock_storage->protocol = protocol;

	scion_sock_storage->socket_fd = socket((int)addr_family, underlying_socket_type, 0);

	if (scion_sock_storage->socket_fd == -1) {
		(void)fprintf(stderr, "ERROR: encountered an unexpected error when creating the socket (%s, code %d)\n",
			strerror(errno), errno);
		ret = SCION_ERR_GENERIC;
		goto cleanup_socket_storage;
	}

	scion_sock_storage->paths = NULL;
	scion_sock_storage->policy = scion_policy_least_hops;
	scion_sock_storage->selector = scion_selector_default;
	scion_sock_storage->current_path = NULL;

	scion_sock_storage->src_addr_len = sizeof(scion_sock_storage->src_addr);

	if (network != NULL) {
		struct scion_underlay probe_underlay;

		// get arbitrary border router
		ret = scion_topology_next_underlay_hop(network->topology, SCION_INTERFACE_ANY, &probe_underlay);
		if (ret != 0) {
			goto cleanup_socket_fd;
		}

		struct sockaddr_storage src_addr;
		socklen_t src_addr_len = sizeof(src_addr);
		// determine the source address by connecting to the border router
		ret = scion_underlay_probe(&probe_underlay, (struct sockaddr *)&src_addr, &src_addr_len);
		if (ret != 0) {
			goto cleanup_socket_fd;
		}

		set_source_address(scion_sock_storage, (struct sockaddr *)&src_addr, src_addr_len, /* with_port */ false);
	}

	*scion_sock = scion_sock_storage;

	return 0;

cleanup_socket_fd:
	(void)close(scion_sock_storage->socket_fd);

cleanup_socket_storage:
	scion_timestamp_state_free(scion_sock_storage->timestamps);
	free(scion_sock_storage);

	return ret;
}

static int refresh_connected_paths(struct scion_socket *scion_sock)
{
	struct scion_path_collection *new_paths;
	int ret = fetch_paths(scion_sock, scion_sock->dst_ia, &new_paths);
	if (ret != 0) {
		return ret;
	}

	if (scion_path_collection_size(new_paths) == 0) {
		scion_path_collection_free(new_paths);
		return SCION_ERR_NO_PATHS;
	}

	if (scion_path_collection_first(new_paths)->path_type == SCION_PATH_TYPE_EMPTY
		&& scion_sock->dst_addr.ss_family != scion_sock->local_addr_family) {
		scion_path_collection_free(new_paths);
		return SCION_ERR_ADDR_FAMILY_MISMATCH;
	}

	scion_sock->current_path = scion_path_collection_carry_over(new_paths, scion_sock->paths, scion_sock->current_path);
	scion_path_collection_free(scion_sock->paths);
	scion_sock->paths = new_paths;

	return 0;
}

int scion_connect(struct scion_socket *scion_sock, const struct sockaddr *addr, socklen_t addrlen, scion_ia ia)
{
	assert(scion_sock);
	assert(addr);
	int ret;

	if (scion_sock->network == NULL) {
		return SCION_ERR_NETWORK_UNKNOWN;
	}

	ret = bind_if_unbound(scion_sock);
	if (ret != 0) {
		return ret;
	}

	struct sockaddr_storage old_dst_addr = scion_sock->dst_addr;
	socklen_t old_dst_addr_len = scion_sock->dst_addr_len;
	scion_ia old_dst_ia = scion_sock->dst_ia;

	(void)memcpy(&scion_sock->dst_addr, addr, addrlen);
	scion_sock->dst_addr_len = addrlen;
	scion_sock->dst_ia = ia;

	ret = refresh_connected_paths(scion_sock);
	if (ret != 0) {
		// The paths still belong to the old destination
		scion_sock->dst_addr = old_dst_addr;
		scion_sock->dst_addr_len = old_dst_addr_len;
		scion_sock->dst_ia = old_dst_ia;
		return ret;
	}

	scion_sock->is_connected = true;

	return 0;
}

static ssize_t scion_sendmsg_path(
	struct scion_socket *scion_sock, struct msghdr *msg, int flags, struct scion_path *path)
{
	assert(scion_sock->protocol == SCION_PROTO_UDP || scion_sock->protocol == SCION_PROTO_SCMP);
	assert(path);
	ssize_t ret;

	if (path->metadata != NULL && path->metadata->expiry <= time(NULL) + PATH_EXPIRATION_THRESHOLD_IN_SECONDS) {
		return SCION_ERR_PATH_EXPIRED;
	}

	// Create SCION Packet. It has the header only, the payload is sent from the buffers of the caller.
	struct scion_packet packet = { 0 };
	packet.version = 0;
	packet.traffic_class = 0;
	packet.flow_id = 1;
	packet.next_hdr = (uint8_t)scion_sock->protocol;
	packet.dst_ia = path->dst;
	packet.src_ia = path->src;
	packet.path_type = (uint8_t)path->path_type;
	if (path->raw_path != NULL) {
		packet.raw_path = path->raw_path->raw;
		packet.raw_path_length = path->raw_path->length;
	}

	// Destination
	struct sockaddr *dst_addr = msg->msg_name;
	if (dst_addr->sa_family == AF_INET && msg->msg_namelen == sizeof(struct sockaddr_in)) {
		// IPv4
		packet.dst_addr_type = SCION_ADDR_TYPE_T4IP;
		packet.raw_dst_addr_length = 4;
		struct sockaddr_in *dst_sockaddr = (struct sockaddr_in *)dst_addr;
		(void)memcpy(packet.raw_dst_addr, &(dst_sockaddr->sin_addr.s_addr), packet.raw_dst_addr_length);
	} else if (dst_addr->sa_family == AF_INET6 && msg->msg_namelen == sizeof(struct sockaddr_in6)) {
		// IPv6
		packet.dst_addr_type = SCION_ADDR_TYPE_T16IP;
		packet.raw_dst_addr_length = 16;
		struct sockaddr_in6 *dst_sockaddr = (struct sockaddr_in6 *)dst_addr;
		(void)memcpy(packet.raw_dst_addr, dst_sockaddr->sin6_addr.s6_addr, packet.raw_dst_addr_length);
	} else {
		// Unsupported destination address type
		return SCION_ERR_ADDR_FAMILY_UNKNOWN;
	}

	// Source
	struct sockaddr_storage src_addr;
	socklen_t src_addr_len = sizeof(src_addr);

	ret = get_source_address(scion_sock, (struct sockaddr *)&src_addr, &src_addr_len);
	if (ret != 0) {
		return ret;
	}

	if (scion_sock->src_addr.ss_family == AF_INET) {
		// IPv4
		packet.src_addr_type = SCION_ADDR_TYPE_T4IP;
		packet.raw_src_addr_length = 4;
		struct sockaddr_in *src_sockaddr = (struct sockaddr_in *)&scion_sock->src_addr;
		(void)memcpy(packet.raw_src_addr, &(src_sockaddr->sin_addr.s_addr), packet.raw_src_addr_length);
	} else if (scion_sock->src_addr.ss_family == AF_INET6) {
		// IPv6
		packet.src_addr_type = SCION_ADDR_TYPE_T16IP;
		packet.raw_src_addr_length = 16;
		struct sockaddr_in6 *src_sockaddr = (struct sockaddr_in6 *)&scion_sock->src_addr;
		(void)memcpy(packet.raw_src_addr, src_sockaddr->sin6_addr.s6_addr, packet.raw_src_addr_length);
	} else {
		// Unsupported source address type
		return SCION_ERR_ADDR_FAMILY_UNKNOWN;
	}

	// Create payload, depending on the protocol.
	size_t data_len = 0;
	for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
		data_len += msg->msg_iov[i].iov_len;
	}

	if (data_len > UINT16_MAX) {
		return SCION_ERR_MSG_TOO_LARGE;
	}

	if ((size_t)msg->msg_iovlen > SCION_IOV_MAX) {
		return SCION_ERR_MSG_TOO_LARGE;
	}

	// The header of the packet is followed by the header of the UDP packet, if there is one, and by the data. They are
	// sent together as the vectors of one message, so nothing is copied or allocated.
	uint8_t packet_hdr[SCION_MAX_HDR_LEN];
	uint8_t udp_hdr[SCION_UDP_HDR_LEN];
	struct iovec iov[SCION_IOV_MAX + 2];
	size_t iov_len = 1;

	if (scion_sock->protocol == SCION_PROTO_UDP) {
		struct scion_udp udp_packet = { 0 };
		udp_packet.data_length = (uint16_t)data_len;

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

		ret = scion_udp_header_serialize(&udp_packet, udp_hdr);
		if (ret != 0) {
			return ret;
		}

		packet.payload_len = scion_udp_len(&udp_packet);
		iov[iov_len].iov_base = udp_hdr;
		iov[iov_len].iov_len = sizeof(udp_hdr);
		iov_len++;
	} else if (scion_sock->protocol == SCION_PROTO_SCMP) {
		packet.payload_len = (uint16_t)data_len;
	}

	for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
		iov[iov_len++] = msg->msg_iov[i];
	}

	size_t hdr_len = sizeof(packet_hdr);
	ret = scion_packet_header_serialize(&packet, packet_hdr, &hdr_len);
	if (ret != 0) {
		return ret;
	}

	iov[0].iov_base = packet_hdr;
	iov[0].iov_len = hdr_len;
	size_t packet_length = hdr_len + packet.payload_len;

	const struct sockaddr *next_hop_addr;
	socklen_t next_hop_addr_length;
	if (path->path_type == SCION_PATH_TYPE_SCION) {
		next_hop_addr = (const struct sockaddr *)&path->underlay_next_hop.addr;
		next_hop_addr_length = path->underlay_next_hop.addrlen;
	} else if (path->path_type == SCION_PATH_TYPE_EMPTY) {
		next_hop_addr = dst_addr;
		next_hop_addr_length = msg->msg_namelen;
	} else {
		return SCION_ERR_PATH_TYPE_INVALID;
	}

	if (next_hop_addr->sa_family != scion_sock->local_addr_family) {
		return SCION_ERR_ADDR_FAMILY_MISMATCH;
	}

	struct timespec transmit_time;
	(void)clock_gettime(CLOCK_REALTIME, &transmit_time);

	do {
		struct msghdr underlying_msg = { 0 };
		underlying_msg.msg_name = (void *)next_hop_addr;
		underlying_msg.msg_namelen = next_hop_addr_length;

		underlying_msg.msg_iovlen = (size_t)iov_len;
		underlying_msg.msg_iov = iov;

		underlying_msg.msg_flags = msg->msg_flags;

		ret = sendmsg(scion_sock->socket_fd, &underlying_msg, flags);
	} while (ret == -1 && errno == EINTR);

	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = SCION_ERR_WOULD_BLOCK;
		} else if (errno == EACCES) {
			ret = SCION_ERR_ADDR_INVALID;
		} else if (errno == EOPNOTSUPP) {
			ret = SCION_ERR_FLAG_NOT_SUPPORTED;
		} else if (errno == ENOMEM) {
			ret = SCION_ERR_MEM_ALLOC_FAIL;
		} else if (errno == ENOBUFS) {
			ret = SCION_ERR_OUTPUT_QUEUE_FULL;
		} else if (errno == EMSGSIZE) {
			ret = SCION_ERR_MSG_TOO_LARGE;
		} else {
			(void)fprintf(stderr, "ERROR: encountered an unexpected error when sending packets (%s, code %d)\n",
				strerror(errno), errno);
			ret = SCION_ERR_SEND_FAIL;
		}

		return ret;
	}

	if (ret > 0) {
		if (scion_sock->debug) {
			(void)printf("Sending packet over the following path:\n");
			scion_path_print(path);
			(void)printf("\n");
		}

		if ((size_t)ret != packet_length) {
			// Packet partially transmitted
			ret = SCION_ERR_SEND_FAIL;
		} else {
			scion_timestamp_record_sent(scion_sock, &transmit_time);
			ret = (ssize_t)data_len;
		}
	}

	return ret;
}

static struct scion_path *select_path(struct scion_socket *scion_sock)
{
	scion_sock->current_path = scion_sock->selector.fn(
		scion_sock->paths, scion_sock->current_path, scion_sock->selector.ctx);
	return scion_sock->current_path;
}

static ssize_t scion_sendmsg_connected_path(struct scion_socket *scion_sock, struct msghdr *msg, int flags)
{
	struct scion_path *path = select_path(scion_sock);
	if (path == NULL) {
		return SCION_ERR_NO_PATHS;
	}

	ssize_t ret = scion_sendmsg_path(scion_sock, msg, flags, path);

	if (ret == SCION_ERR_PATH_EXPIRED) {
		ret = refresh_connected_paths(scion_sock);
		if (ret != 0) {
			return ret;
		}

		path = select_path(scion_sock);
		if (path == NULL) {
			return SCION_ERR_NO_PATHS;
		}

		ret = scion_sendmsg_path(scion_sock, msg, flags, path);
	}

	return ret;
}

// Gets the paths to a destination that the socket is not connected to. They are fetched if they are not in the cache
// or if they need to be refreshed.
static int cached_paths(
	struct scion_socket *scion_sock, scion_ia dst_ia, bool refresh, struct scion_path_collection **paths)
{
	if (!refresh) {
		*paths = scion_path_cache_get(&scion_sock->path_cache, dst_ia);
		if (*paths != NULL) {
			return 0;
		}
	}

	int ret = fetch_paths(scion_sock, dst_ia, paths);
	if (ret != 0) {
		return ret;
	}

	if (scion_path_collection_size(*paths) == 0) {
		scion_path_collection_free(*paths);
		return SCION_ERR_NO_PATHS;
	}

	scion_path_cache_put(&scion_sock->path_cache, dst_ia, *paths);
	return 0;
}

static ssize_t scion_sendmsg_cached_path(
	struct scion_socket *scion_sock, struct msghdr *msg, int flags, scion_ia dst_ia)
{
	struct scion_path_collection *paths;
	ssize_t ret = cached_paths(scion_sock, dst_ia, /* refresh: */ false, &paths);
	if (ret != 0) {
		return ret;
	}

	ret = scion_sendmsg_path(scion_sock, msg, flags, scion_path_collection_first(paths));

	if (ret == SCION_ERR_PATH_EXPIRED) {
		ret = cached_paths(scion_sock, dst_ia, /* refresh: */ true, &paths);
		if (ret != 0) {
			return ret;
		}

		ret = scion_sendmsg_path(scion_sock, msg, flags, scion_path_collection_first(paths));
	}

	return ret;
}

ssize_t scion_send(struct scion_socket *scion_sock, const void *buf, size_t size, int flags)
{
	if (scion_sock->network == NULL) {
		return SCION_ERR_NETWORK_UNKNOWN;
	}

	return scion_sendto(scion_sock, buf, size, flags, NULL, 0, 0, NULL);
}

ssize_t scion_sendto(struct scion_socket *scion_sock, const void *buf, size_t size, int flags,
	const struct sockaddr *dst_addr, socklen_t addrlen, scion_ia dst_ia, struct scion_path *path)
{
	assert(scion_sock);
	assert(size == 0 || buf);

	struct iovec iov = { 0 };
	iov.iov_base = (void *)buf;
	iov.iov_len = size;

	struct msghdr msg = { .msg_name = (void *)dst_addr,
		.msg_namelen = addrlen,
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = NULL,
		.msg_controllen = 0,
		.msg_flags = 0 };

	return scion_sendmsg(scion_sock, &msg, flags, dst_ia, path);
}

ssize_t scion_sendmsg(
	struct scion_socket *scion_sock, const struct msghdr *msg, int flags, scion_ia dst_ia, struct scion_path *path)
{
	assert(msg);

	struct msghdr underlying_msg = *msg;

	ssize_t ret;

	if (msg->msg_control != NULL && msg->msg_controllen > 0) {
		return SCION_ERR_CONTROL_MSG_NOT_IMPLEMENTED;
	}

	if (path == NULL && scion_sock->network == NULL) {
		return SCION_ERR_NETWORK_UNKNOWN;
	}

	if ((flags & IMPLEMENTED_SEND_FLAGS) != flags) {
		return SCION_ERR_FLAG_NOT_IMPLEMENTED;
	}

	ret = bind_if_unbound(scion_sock);
	if (ret != 0) {
		return ret;
	}

	if (msg->msg_name == NULL) {
		if (!scion_sock->is_connected) {
			return SCION_ERR_NOT_CONNECTED;
		}

		underlying_msg.msg_name = (struct sockaddr *)&scion_sock->dst_addr;
		underlying_msg.msg_namelen = scion_sock->dst_addr_len;
		dst_ia = scion_sock->dst_ia;
	}

	if (path != NULL && path->dst != dst_ia) {
		return SCION_ERR_DST_MISMATCH;
	}

	// Handle path, there are 3 different cases:
	// 1. No path was provided but destination IA matches the connected IA
	//    --> Use connected path
	// 2. No path was provided and destination IA does not match the connected IA
	//    --> Use the cached paths to the destination, which are fetched the first time
	// 3. A path was provided as an argument
	//    --> Use the provided path
	if (path == NULL) {
		if (scion_sock->is_connected && scion_sock->dst_ia == dst_ia) {
			return scion_sendmsg_connected_path(scion_sock, &underlying_msg, flags);
		}

		return scion_sendmsg_cached_path(scion_sock, &underlying_msg, flags, dst_ia);
	}

	return scion_sendmsg_path(scion_sock, &underlying_msg, flags, path);
}

ssize_t scion_recv(struct scion_socket *scion_sock, void *buf, size_t size, int flags)
{
	return scion_recvfrom(scion_sock, buf, size, flags, NULL, NULL, NULL, NULL);
}

ssize_t scion_recvfrom(struct scion_socket *scion_sock, void *buf, size_t size, int flags, struct sockaddr *src_addr,
	socklen_t *addrlen, scion_ia *src_ia, struct scion_path *path)
{
	assert(scion_sock);
	assert(buf);

	struct msghdr msg = { 0 };
	msg.msg_name = src_addr;

	if (src_addr != NULL) {
		assert(addrlen);
		msg.msg_namelen = *addrlen;
	}

	struct iovec iov = { 0 };
	iov.iov_base = buf;
	iov.iov_len = size;

	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	msg.msg_control = NULL;
	msg.msg_controllen = 0;

	msg.msg_flags = 0;

	ssize_t ret = scion_recvmsg(scion_sock, &msg, flags, src_ia, path);

	if (ret > 0) {
		if (addrlen) {
			*addrlen = msg.msg_namelen;
		}
	}

	return ret;
}

#ifdef MSG_ERRQUEUE
// Receives a message from the error queue of the underlying socket. That is where the kernel puts the transmit
// timestamps. The message is not a SCION packet, so it is returned as it is.
static ssize_t recv_error_queue(struct scion_socket *scion_sock, struct msghdr *msg, int flags)
{
	ssize_t ret;
	do {
		ret = recvmsg(scion_sock->socket_fd, msg, flags);
	} while (ret == -1 && errno == EINTR);

	if (ret < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			return SCION_ERR_WOULD_BLOCK;
		}

		(void)fprintf(stderr, "ERROR: encountered an unexpected error when receiving packets (%s, code %d)\n",
			strerror(errno), errno);
		return SCION_ERR_RECV_FAIL;
	}

	return ret;
}
#endif

// Whether the library implements a control message of the underlying socket.
static bool is_implemented_control_message(const struct cmsghdr *cmsg)
{
#ifdef SCM_TIMESTAMPING
	return cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING;
#else
	(void)cmsg;
	return false;
#endif
}

// Removes the control messages that the library does not implement, and moves the others to the start of the buffer.
static void remove_unimplemented_control_messages(struct msghdr *msg)
{
	char *control = msg->msg_control;
	size_t kept = 0;

	struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg);
	while (cmsg != NULL) {
		// A message that is moved is overwritten, so the next one is looked up first.
		struct cmsghdr *next = CMSG_NXTHDR(msg, cmsg);

		if (is_implemented_control_message(cmsg) && cmsg->cmsg_len >= CMSG_LEN(0)) {
			size_t offset = (size_t)((char *)cmsg - control);
			size_t space = CMSG_SPACE(cmsg->cmsg_len - CMSG_LEN(0));
			if (space > msg->msg_controllen - offset) {
				space = msg->msg_controllen - offset;
			}

			(void)memmove(control + kept, cmsg, space);
			kept += space;
		}

		cmsg = next;
	}

	msg->msg_controllen = (socklen_t)kept;
}

// The maximum length of a SCION packet with an SCMP message, so an SCMP error is received whole in a buffer of it.
// https://github.com/scionproto/scion/blob/1774186e80e43118a2f9a3f7e989d4af3479a937/pkg/slayers/scmp.go#L39
#define SCION_RECV_HEAD_LEN 1232

_Static_assert(SCION_RECV_HEAD_LEN >= SCION_MAX_HDR_LEN + SCION_UDP_HDR_LEN, "the headers must fit in the head buffer");

// Finds the buffer of a message that contains the byte at the offset, and makes the offset relative to that buffer.
static size_t find_iov(const struct iovec *iov, size_t *offset)
{
	size_t i = 0;
	while (*offset >= iov[i].iov_len) {
		*offset -= iov[i].iov_len;
		i++;
	}

	return i;
}

// Moves bytes in the buffers of a message to a later offset. They are moved from the end, so they are not overwritten
// before they are moved.
static void iov_move_forward(const struct iovec *iov, size_t dst, size_t src, size_t len)
{
	while (len > 0) {
		size_t src_offset = src + len - 1;
		size_t src_i = find_iov(iov, &src_offset);
		size_t dst_offset = dst + len - 1;
		size_t dst_i = find_iov(iov, &dst_offset);

		// The last bytes that are in one buffer both where they are and where they go
		size_t chunk = src_offset < dst_offset ? src_offset + 1 : dst_offset + 1;
		if (chunk > len) {
			chunk = len;
		}

		(void)memmove((uint8_t *)iov[dst_i].iov_base + dst_offset + 1 - chunk,
			(uint8_t *)iov[src_i].iov_base + src_offset + 1 - chunk, chunk);
		len -= chunk;
	}
}

// Copies bytes to the start of the buffers of a message.
static void copy_to_iov(const struct iovec *iov, const uint8_t *src, size_t len)
{
	for (size_t i = 0; len > 0; i++) {
		size_t chunk = iov[i].iov_len < len ? iov[i].iov_len : len;
		(void)memcpy(iov[i].iov_base, src, chunk);
		src += chunk;
		len -= chunk;
	}
}

// Puts the data of a received packet at the start of the buffers of a message, as much as fits. The kernel received
// the first part of the data in the head buffer and the rest at the start of the buffers. Returns the length that fits.
static size_t move_data_to_iov(
	const struct iovec *iov, size_t buf_len, const uint8_t *head_data, size_t head_data_len, size_t rest_len)
{
	size_t first_len = head_data_len < buf_len ? head_data_len : buf_len;
	size_t moved_len = rest_len < buf_len - first_len ? rest_len : buf_len - first_len;

	if (first_len > 0) {
		iov_move_forward(iov, first_len, 0, moved_len);
		copy_to_iov(iov, head_data, first_len);
	}

	return first_len + moved_len;
}

ssize_t scion_recvmsg(
	struct scion_socket *scion_sock, struct msghdr *msg, int flags, scion_ia *src_ia, struct scion_path *path)
{
	assert(scion_sock);
	assert(msg);

	ssize_t ret;
	size_t recv_len = 0;

	if ((flags & IMPLEMENTED_RECV_FLAGS) != flags) {
		return SCION_ERR_FLAG_NOT_IMPLEMENTED;
	}

#ifdef MSG_ERRQUEUE
	if ((flags & MSG_ERRQUEUE) != 0) {
		return recv_error_queue(scion_sock, msg, flags);
	}
#endif

	if ((size_t)msg->msg_iovlen > SCION_IOV_MAX) {
		return SCION_ERR_MSG_TOO_LARGE;
	}

	size_t buf_len = 0;
	for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
		buf_len += msg->msg_iov[i].iov_len;
	}

	bool received_anticipated_packet = false;
	while (!received_anticipated_packet) {
		struct sockaddr_storage sender_addr;
		socklen_t sender_addr_len;

		struct sockaddr_storage underlay_addr;

		struct msghdr raw_msg = { 0 };
		raw_msg.msg_name = &underlay_addr;
		raw_msg.msg_namelen = sizeof(underlay_addr);

		// The headers are received in the head buffer and the packet continues in the buffers of the caller, so the
		// data is copied once, to the start of the buffers. An SCMP error is needed whole, even if the buffers are
		// smaller, and it fits in the head buffer.
		uint8_t head[SCION_RECV_HEAD_LEN];
		struct iovec iov[SCION_IOV_MAX + 1];
		iov[0].iov_base = head;
		iov[0].iov_len = sizeof(head);
		for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
			iov[i + 1] = msg->msg_iov[i];
		}

		raw_msg.msg_iov = iov;
		raw_msg.msg_iovlen = msg->msg_iovlen + 1;

		raw_msg.msg_control = msg->msg_control;
		raw_msg.msg_controllen = msg->msg_controllen;

		do {
			ret = recvmsg(scion_sock->socket_fd, &raw_msg, flags);
		} while (ret == -1 && errno == EINTR);

		if (ret < 0) {
			if (errno == EAGAIN || errno == EWOULDBLOCK) {
				ret = SCION_ERR_WOULD_BLOCK;
			} else {
				(void)fprintf(stderr, "ERROR: encountered an unexpected error when receiving packets (%s, code %d)\n",
					strerror(errno), errno);
				ret = SCION_ERR_RECV_FAIL;
			}

			return ret;
		}

		size_t received_len = (size_t)ret;
		size_t head_len = received_len < sizeof(head) ? received_len : sizeof(head);

		struct scion_packet packet = { 0 };
		ret = scion_packet_header_deserialize(head, head_len, &packet);
		if (ret != 0) {
			// Ignore packet
			ret = 0;
			goto cleanup_packet;
		}

		// A packet that is shorter than its header announces is malformed, unless it did not fit in the buffers
		size_t hdr_len = scion_packet_hdr_len(&packet);
		bool truncated = (raw_msg.msg_flags & MSG_TRUNC) != 0;
		if (!truncated && received_len < hdr_len + packet.payload_len) {
			// Ignore packet
			goto cleanup_packet;
		}

		// The part of the payload that was received, and the part of it that is in the head buffer
		size_t payload_len = received_len - hdr_len;
		if (payload_len > packet.payload_len) {
			payload_len = packet.payload_len;
		}
		size_t head_payload_len = head_len - hdr_len;
		if (head_payload_len > payload_len) {
			head_payload_len = payload_len;
		}

		uint16_t src_port;
		// Where the data starts in the payload, and its length as the headers announce it
		size_t data_offset;
		size_t data_len;

		// Deserialize packet
		if (packet.next_hdr == 17) {
			struct scion_udp udp = { 0 };
			ret = scion_udp_header_deserialize(packet.payload, (uint16_t)head_payload_len, &udp);
			if (ret != 0 || scion_udp_len(&udp) > packet.payload_len) {
				// Ignore packet
				ret = 0;
				goto cleanup_packet;
			}

			src_port = udp.src_port;
			data_offset = SCION_UDP_HDR_LEN;
			data_len = udp.data_length;
		} else if (packet.next_hdr == 202) {
			// SCMP message
			src_port = 0; // No port on SCMP
			data_offset = 0;
			data_len = packet.payload_len;
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

		// SCMP error received. It is in the head buffer, which is as long as an SCMP error can be.
		if (packet.next_hdr == SCION_PROTO_SCMP && scion_scmp_is_error(packet.payload, (uint16_t)head_payload_len)) {
			// Mark the affected paths as down and trigger the SCMP error handler
			if (scion_sock->paths != NULL || scion_sock->scmp_error_handler.fn != NULL) {
				struct scion_scmp_error scmp_error;
				const uint8_t *quoted_packet;
				ret = scion_scmp_error_parse(packet.payload, head_payload_len, &scmp_error, &quoted_packet);
				if (ret == 0) {
					// The handler only reads the quoted packet, which is in the buffer of this function
					scmp_error.packet = (uint8_t *)quoted_packet;
					if (scion_sock->paths != NULL) {
						scion_path_collection_mark_down(scion_sock->paths, &scmp_error);
					}
					if (scion_sock->scmp_error_handler.fn != NULL) {
						scion_sock->scmp_error_handler.fn(&scmp_error, scion_sock->scmp_error_handler.ctx);
					}
				} else if (scion_sock->debug) {
					(void)fprintf(stderr, "Ignoring an SCMP error message that cannot be parsed (%s, code %d)\n",
						scion_strerror((int)ret), (int)ret);
				}
			}

			// Ignore packet
			ret = 0;
			goto cleanup_packet;
		}

		// Packet has unexpected protocol
		if (packet.next_hdr != scion_sock->protocol) {
			// Ignore packet
			goto cleanup_packet;
		}

		// Socket is connected, but packet does not come from connected destination
		if (scion_sock->is_connected
			&& (packet.src_ia != scion_sock->dst_ia
				|| !sockaddr_eq(
					scion_sock->protocol, (struct sockaddr *)&scion_sock->dst_addr, (struct sockaddr *)&sender_addr))) {
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

		// The data that was received, and the part of it that is in the head buffer
		size_t received_data_len = payload_len - data_offset;
		if (received_data_len > data_len) {
			received_data_len = data_len;
		}
		size_t head_data_len = head_payload_len - data_offset;
		if (head_data_len > received_data_len) {
			head_data_len = received_data_len;
		}
		recv_len = move_data_to_iov(
			msg->msg_iov, buf_len, packet.payload + data_offset, head_data_len, received_data_len - head_data_len);

		msg->msg_flags = raw_msg.msg_flags & ~MSG_TRUNC;
		if (recv_len < data_len) {
			msg->msg_flags |= MSG_TRUNC;
		}
		msg->msg_controllen = raw_msg.msg_controllen;
		remove_unimplemented_control_messages(msg);

		if (msg->msg_name != NULL) {
			if (msg->msg_namelen < sender_addr_len) {
				ret = SCION_ERR_ADDR_BUF_TOO_SMALL;
				goto cleanup_packet;
			}

			msg->msg_namelen = sender_addr_len;
			(void)memcpy(msg->msg_name, &sender_addr, sender_addr_len);
		}

		if (src_ia != NULL) {
			*src_ia = packet.src_ia;
		}

		if (path != NULL) {
			ret = scion_path_set_raw(path, packet.src_ia, packet.dst_ia, (enum scion_path_type)packet.path_type,
				packet.raw_path, packet.raw_path_length);
			if (ret != 0) {
				return ret;
			}

			path->underlay_next_hop.addr_family = scion_sock->local_addr_family;
			path->underlay_next_hop.addrlen = raw_msg.msg_namelen;
			(void)memcpy(&path->underlay_next_hop.addr, raw_msg.msg_name, raw_msg.msg_namelen);
		}

cleanup_packet:

		// Return on error
		if (ret < 0) {
			return ret;
		}

		if (!received_anticipated_packet && (flags & MSG_PEEK) != 0) {
			// A peek leaves the packet queued, so consume an ignored one to get to the next packet
			uint8_t discarded;
			do {
				ret = recv(scion_sock->socket_fd, &discarded, sizeof(discarded), MSG_DONTWAIT);
			} while (ret == -1 && errno == EINTR);
			if (ret < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
				return SCION_ERR_RECV_FAIL;
			}
		}
	}

	return (ssize_t)recv_len;
}

int scion_getsockopt(const struct scion_socket *scion_sock, int level, int optname, void *optval, socklen_t *optlen)
{
	assert(scion_sock);
	assert(optval);
	assert(optlen);
	int ret = 0;

	if (level == SOL_SOCKET && optname == SCION_SO_DEBUG) {
		if (*optlen < sizeof(bool)) {
			return SCION_ERR_BUF_TOO_SMALL;
		}

		*(bool *)optval = scion_sock->debug;
	} else {
		ret = getsockopt(scion_sock->socket_fd, level, optname, optval, optlen);
		if (ret == -1) {
			if (errno == EFAULT) {
				ret = SCION_ERR_BUF_TOO_SMALL;
			} else if (errno == EINVAL || errno == ENOPROTOOPT) {
				ret = SCION_ERR_SOCK_OPT_INVALID;
			} else {
				(void)fprintf(stderr,
					"ERROR: encountered an unexpected error when getting socket option (%s, code %d)\n",
					strerror(errno), errno);
				ret = SCION_ERR_GENERIC;
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
				ret = SCION_ERR_BUF_TOO_SMALL;
			} else if (errno == EINVAL || errno == ENOPROTOOPT) {
				ret = SCION_ERR_SOCK_OPT_INVALID;
			} else {
				(void)fprintf(stderr,
					"ERROR: encountered an unexpected error when setting socket option (%s, code %d)\n",
					strerror(errno), errno);
				ret = SCION_ERR_GENERIC;
			}
		}
#ifdef SO_TIMESTAMPING
		else if (level == SOL_SOCKET && optname == SO_TIMESTAMPING && optlen >= sizeof(int)) {
			int flags;
			(void)memcpy(&flags, optval, sizeof(flags));
			scion_timestamp_flags_changed(scion_sock, flags);
		}
#endif
	}

	return ret;
}

int scion_bind(struct scion_socket *scion_sock, const struct sockaddr *addr, socklen_t addrlen)
{
	assert(scion_sock);
	assert(addr);
	int ret;

	if (scion_sock->is_bound) {
		return SCION_ERR_ALREADY_BOUND;
	}

	if (!(addr->sa_family == SCION_AF_INET || addr->sa_family == SCION_AF_INET6)) {
		return SCION_ERR_ADDR_FAMILY_UNKNOWN;
	}

	if (addr->sa_family != scion_sock->local_addr_family) {
		return SCION_ERR_ADDR_FAMILY_MISMATCH;
	}

	ret = bind(scion_sock->socket_fd, addr, addrlen);
	if (ret != 0) {
		if (errno == EADDRINUSE) {
			return SCION_ERR_ADDR_IN_USE;
		}

		if (errno == EADDRNOTAVAIL) {
			return SCION_ERR_ADDR_NOT_AVAILABLE;
		}

		(void)fprintf(stderr, "ERROR: encountered an unexpected error when binding (code: %d)\n", errno);
		return SCION_ERR_GENERIC;
	}

	struct sockaddr_storage src_addr;
	socklen_t src_addr_len = sizeof(src_addr);

	ret = getsockname(scion_sock->socket_fd, (struct sockaddr *)&src_addr, &src_addr_len);
	if (ret != 0) {
		(void)fprintf(stderr, "ERROR: encountered an unexpected error after binding (code: %d)\n", errno);
		return SCION_ERR_GENERIC;
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

int scion_getsockname(const struct scion_socket *scion_sock, struct sockaddr *addr, socklen_t *addrlen, scion_ia *ia)
{
	assert(scion_sock);

	if (!scion_sock->is_bound) {
		return SCION_ERR_NOT_BOUND;
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
			return SCION_ERR_ADDR_BUF_TOO_SMALL;
		}

		(void)memcpy(addr, &src_addr, src_addr_len);
		*addrlen = src_addr_len;
	}

	if (ia != NULL) {
		if (scion_sock->network == NULL) {
			return SCION_ERR_NETWORK_UNKNOWN;
		}

		*ia = scion_sock->network->topology->ia;
	}

	return 0;
}

int scion_getsockfd(const struct scion_socket *scion_sock, int *fd)
{
	assert(scion_sock);
	assert(fd);

	*fd = scion_sock->socket_fd;

	return 0;
}

int scion_setsockerrhandler(struct scion_socket *scion_sock, const struct scion_scmp_error_handler *handler)
{
	assert(scion_sock);
	assert(handler);

	scion_sock->scmp_error_handler = *handler;

	return 0;
}

int scion_setsockpolicy(struct scion_socket *scion_sock, const struct scion_policy *policy)
{
	assert(scion_sock);
	assert(policy);
	int ret = 0;

	scion_sock->policy = *policy;

	// The cached paths were chosen by the old policy
	scion_path_cache_clear(&scion_sock->path_cache);

	if (scion_sock->is_connected) {
		ret = refresh_connected_paths(scion_sock);
	}

	return ret;
};

int scion_setsockselector(struct scion_socket *scion_sock, const struct scion_selector *selector)
{
	assert(scion_sock);
	assert(selector);
	assert(selector->fn);

	scion_sock->selector = *selector;

	return 0;
}
