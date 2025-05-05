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
#include <stdint.h>
#include <sys/socket.h>

#include "common/isd_as.h"
#include "data_plane/path.h"
#include "scion/scion.h"
#include "util/linked_list.h"

#define SCION_INTERFACE_ANY ((scion_interface)0)

typedef uint16_t scion_interface;

struct scion_topology {
	scion_ia ia;
	bool local_core;
	char *cs_ip;
	uint16_t cs_port;
	enum scion_addr_family local_addr_family;
	struct scion_linked_list *border_routers;
};

struct scion_border_router {
	scion_interface ifid;
	char *ip;
	uint16_t port;
};

/*
 * FUNCTION: scion_topology_next_underlay_hop
 * -----------------
 * Uses the topology file and a provided interface id to determine the next hop. If SCION_INTERFACE_ANY is used, an
 * arbitrary underlay is returned.
 *
 * Arguments:
 * 		- struct scion_topology  *t: Pointer to a scion_topology struct, which contains the list of
 * 		  border routers.
 * 		- scion_interface ifid: Interface ID of the next hop.
 * 		- struct scion_path_underlay *underlay: Pointer to memory where the underlay is stored.
 *
 * Returns:
 *      - An integer status code, 0 for success or an error code as defined in error.h.
 */
/**
 * Uses the topology file and a provided interface id to determine the next hop. If SCION_INTERFACE_ANY is used, an
 * arbitrary underlay is returned.
 * @param[in] t The topology.
 * @param[in] ifid The interface, or @link SCION_INTERFACE_ANY @endlink.
 * @param[out] underlay The underlay of the next hop.
 * @return 0 on success, a negative error code on failure.
 */
int scion_topology_next_underlay_hop(struct scion_topology *t, scion_interface ifid, struct scion_underlay *underlay);

/*
 * FUNCTION: scion_topology_is_local_as_core
 * -----------------
 * Uses the topology file to check if the local AS is a CORE AS or not.
 *
 * Arguments:
 * 		- struct scion_topology  *t: Pointer to a scion_topology struct, which contains the needed
 * 		  information.
 *
 * Returns:
 *      - A Boolean: true if the local AS is a CORE AS, false if it's not a CORE AS.
 */
bool scion_topology_is_local_as_core(struct scion_topology *t);

scion_ia scion_topology_get_local_ia(struct scion_topology *topo);

int scion_topology_from_file(struct scion_topology **topology, const char *path);

void scion_topology_free(struct scion_topology *topo);
