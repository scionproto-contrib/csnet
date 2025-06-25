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

#include <inttypes.h>
#include <scion/scion.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
	int ret;

	printf("\nHello SCION on Linux\n\n");

	const char *topology_path = "bootstrapped_topology.json";
	ret = scion_bootstrap(topology_path);
	if (ret != 0) {
		printf("Error: bootstrapping failed\n");
		return EXIT_FAILURE;
	}

	struct scion_topology *topology;
	ret = scion_topology_from_file(&topology, topology_path);
	if (ret != 0) {
		printf("Error: failed to load topology from file\n");
		return EXIT_FAILURE;
	}

	char ia_str[SCION_IA_STRLEN];
	ret = scion_ia_str(scion_topology_get_local_ia(topology), ia_str, sizeof(ia_str));
	if (ret != 0) {
		printf("Error: failed to get local ia from topology\n");
		return EXIT_FAILURE;
	}
	printf("The local IA is: %s\n", ia_str);

	scion_topology_free(topology);

	printf("Done\n");

	return ret;
}
