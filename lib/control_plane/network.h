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

#pragma once

#include "control_plane/topology.h"
#include "scion/scion.h"

struct scion_network {
	struct scion_topology *topology;
	struct sockaddr_storage src_addr;
	socklen_t src_addr_len;
	bool src_addr_set;
};

int scion_network(struct scion_network **net, struct scion_topology *topology);

void scion_network_free(struct scion_network *net);

int scion_network_set_addr(struct scion_network *net, const struct sockaddr *addr, socklen_t addr_len);

int scion_network_get_addr(struct scion_network *net, struct sockaddr *addr, socklen_t *addr_len);
