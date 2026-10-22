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
#include "scion/scion_policy.h"
#include "scion/scion_scmp.h"

#define SCION_SO_DEBUG 200

struct scion_socket_timestamps;

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
	struct scion_socket_timestamps *timestamps;
};
