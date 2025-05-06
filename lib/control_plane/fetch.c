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

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "control_plane/fetch.h"
#include "control_plane/graph.h"
#include "control_plane/network.h"
#include "control_plane/segment.h"
#include "control_plane/topology.h"
#include "data_plane/path.h"
#include "util/linked_list.h"

/*
 * FUNCTION: scion_fetch_paths
 * -----------------
 * Returns a list of available paths between a given source AS and a given destination AS by
 * fetching the required path segments from the local Control Server.
 *
 * Arguments:
 *      - struct scion_topology *t: Pointer to scion_topology struct, containing information about the local AS
 * 		  (such as control server ip, etc.).
 *      - ScionIA src: source AS.
 *      - ScionIA dst: destination AS.
 *      - struct scion_linked_list *paths: Pointer to a scion_linked_list into which the resulting scion_path structs,
 *        which represent the available paths, will be stored.
 *
 * Returns:
 *      - An integer status code, 0 for success or an error code as defined in error.h.
 */
int scion_fetch_paths(struct scion_network *network, scion_ia dst, uint opt, struct scion_path_collection **paths)
{
	assert(network);
	assert(paths);

	int ret;

	struct scion_topology *t = network->topology;
	scion_ia src = t->ia;

	struct scion_path_collection *new_paths;
	ret = scion_path_collection_init(&new_paths);
	if (ret != 0) {
		return ret;
	}

	if (src == dst) {
		struct scion_path *empty_path = malloc(sizeof(*empty_path));
		if (empty_path == NULL) {
			return SCION_MEM_ALLOC_FAIL;
		}
		empty_path->src = 0;
		empty_path->dst = 0;
		empty_path->path_type = SCION_PATH_TYPE_EMPTY;
		empty_path->raw_path = NULL;
		empty_path->metadata = NULL;
		empty_path->weight = 0;
		scion_list_append(new_paths->list, empty_path);

		ret = 0;
		goto exit;
	}

	bool src_is_core = scion_topology_is_local_as_core(t);
	bool dst_is_core;
	ret = scion_dst_core_check(t->cs_ip, t->cs_ip, t->cs_port, src, dst);
	if (ret < 0) {
		goto exit;
	} else if (ret == 0) {
		dst_is_core = false;
	} else {
		dst_is_core = true;
	}

	struct scion_split_segments split_requests;
	ret = scion_split_segments(src, src_is_core, dst, dst_is_core, &split_requests);
	if (ret != 0) {
		goto exit;
	}

	struct scion_path_segment_list ups_list;
	struct scion_path_segment_list cores_list;
	struct scion_path_segment_list downs_list;

	if (split_requests.has_up) {
		ret = scion_path_segments_lookup(
			t->cs_ip, t->cs_ip, t->cs_port, split_requests.up_src, split_requests.up_dst, &ups_list);
		if (ret != 0) {
			goto cleanup_ups;
		}
	} else {
		ups_list.list = NULL;
		ups_list.length = 0;
	}

	if (split_requests.has_core) {
		ret = scion_path_segments_lookup(
			t->cs_ip, t->cs_ip, t->cs_port, split_requests.core_src, split_requests.core_dst, &cores_list);
		if (ret != 0) {
			goto cleanup_cores;
		}
	} else {
		cores_list.list = NULL;
		cores_list.length = 0;
	}

	if (split_requests.has_down) {
		ret = scion_path_segments_lookup(
			t->cs_ip, t->cs_ip, t->cs_port, split_requests.down_src, split_requests.down_dst, &downs_list);
		if (ret != 0) {
			goto cleanup_downs;
		}
	} else {
		downs_list.list = NULL;
		downs_list.length = 0;
	}

	ret = scion_build_paths(src, dst, network->topology, ups_list.list, ups_list.length, cores_list.list,
		cores_list.length, downs_list.list, downs_list.length, new_paths->list, opt);

cleanup_downs:
	scion_free_pathseglist_internal(&downs_list);

cleanup_cores:
	scion_free_pathseglist_internal(&cores_list);

cleanup_ups:
	scion_free_pathseglist_internal(&ups_list);

exit:
	if (ret != 0) {
		scion_path_collection_free(new_paths);
	} else {
		*paths = new_paths;
	}

	return ret;
}
