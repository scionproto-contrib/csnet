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

#include <scion/scion.h>

int main(int argc, char *argv[])
{
	int ret;

	printf("\nHello SCION on Linux\n");

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

	// ### Showpaths  Example ###
	scion_ia dst_ia = 0x2ff0000000222;

	struct scion_path_collection *paths;
	ret = scion_path_collection_fetch(network, dst_ia, SCION_FETCH_OPT_DEBUG, &paths);
	if (ret != 0) {
		printf("ERROR: Failed to fetch paths with error code: %d\n", ret);
		ret = EXIT_FAILURE;
		goto cleanup_network;
	}

	printf("\nPath lookup from ");
	scion_ia_print(scion_topology_get_local_ia(topology));
	printf(" to ");
	scion_ia_print(dst_ia);
	printf("\n");
	scion_path_collection_print(paths);

	printf("\nDone.\n");
	ret = EXIT_SUCCESS;

	scion_path_collection_free(paths);

cleanup_network:
	scion_network_free(network);

cleanup_topology:
	scion_topology_free(topology);

	return ret;
}
