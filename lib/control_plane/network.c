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

int scion_network(struct scion_network **net, struct scion_topology *topology)
{
	assert(net);
	assert(topology);

	struct scion_network *new_net = malloc(sizeof(struct scion_network));
	if (new_net == NULL) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}

	new_net->topology = topology;

	*net = new_net;

	return 0;
}

void scion_network_free(struct scion_network *net)
{
	free(net);
}

enum scion_addr_family scion_network_get_local_addr_family(struct scion_network *net)
{
	return net->topology->local_addr_family;
}
