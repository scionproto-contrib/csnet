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

#pragma once

#include <stdbool.h>
#include <sys/socket.h>

#include "common/isd_as.h"
#include "data_plane/path.h"
#include "scion/scion.h"

#define SCION_SO_DEBUG 200

typedef void scion_socket_scmp_error_cb(uint8_t *buf, size_t size, void *ctx);

struct scion_socket {
	int socket_fd;
	enum scion_addr_family local_addr_family;
	int type;
	enum scion_proto protocol;
	struct scion_network *network;
	struct sockaddr_storage src_addr;
	socklen_t src_addr_len;
	bool is_src_addr_set;
	struct sockaddr_storage dst_addr;
	socklen_t dst_addr_len;
	scion_ia dst_ia;
	struct scion_path_collection *paths;
	struct scion_policy policy;
	scion_socket_scmp_error_cb *scmp_error_cb;
	void *scmp_error_ctx;
	bool is_bound;
	bool is_connected;
	bool debug;
};

int scion_socket(struct scion_socket **scion_sock, enum scion_addr_family addr_family, int type,
	enum scion_proto protocol, struct scion_network *network);

int scion_bind(struct scion_socket *scion_sock, const struct sockaddr *addr, socklen_t addrlen);

int scion_connect(struct scion_socket *scion_sock, const struct sockaddr *addr, socklen_t addrlen, scion_ia ia);

ssize_t scion_send(struct scion_socket *scion_sock, const void *buf, size_t size, int flags);

ssize_t scion_sendto(struct scion_socket *scion_sock, const void *buf, size_t size, int flags,
	const struct sockaddr *dst_addr, socklen_t addrlen, scion_ia dst_ia, struct scion_path *path);

ssize_t scion_sendmsg(
	struct scion_socket *scion_sock, const struct msghdr *msg, int flags, scion_ia dst_ia, struct scion_path *path);

ssize_t scion_recv(struct scion_socket *scion_sock, void *buf, size_t size, int flags);

ssize_t scion_recvfrom(struct scion_socket *scion_sock, void *buf, size_t size, int flags, struct sockaddr *src_addr,
	socklen_t *addrlen, scion_ia *src_ia, struct scion_path **path);

ssize_t scion_recvmsg(
	struct scion_socket *scion_sock, struct msghdr *msg, int flags, scion_ia *src_ia, struct scion_path **path);

int scion_close(struct scion_socket *scion_sock);

int scion_getsockopt(struct scion_socket *scion_sock, int level, int optname, void *optval, socklen_t *optlen);

int scion_setsockopt(struct scion_socket *scion_sock, int level, int optname, const void *optval, socklen_t optlen);

int scion_getsockname(struct scion_socket *scion_sock, struct sockaddr *addr, socklen_t *addrlen, scion_ia *ia);

int scion_getsockfd(struct scion_socket *scion_sock, int *fd);

int scion_setsockerrcb(struct scion_socket *scion_sock, scion_socket_scmp_error_cb cb, void *ctx);

int scion_setsockpolicy(struct scion_socket *scion_sock, struct scion_policy policy);

void scion_addr_print(const struct sockaddr *addr, scion_ia ia);
