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

#include "scion/common/path_segment.h"
#include "scion/control_plane/topology.h"
#include "scion/data_plane/path.h"
#include "scion/util/linked_list.h"

/**
 * Builds the available paths between two ASes given the available segments.
 * @param[in] src The source IA.
 * @param[in] dst The destination IA.
 * @param[in] topology The local topology.
 * @param[in] ups The array of available UP segments.
 * @param[in] ups_length The length of the UP segment array.
 * @param[in] cores The array of available CORE segments.
 * @param[in] cores_length The length of the CORE segment array.
 * @param[in] downs The array of available DOWN segments.
 * @param[in] downs_length The length of the DOWN segment array.
 * @param[in,out] paths Must contain an initialized linked list when calling. Contains all the available paths on
 * return.
 * @param[in] opt The path fetching options. Must be 0 if no flags should be used.
 * @return 0 on success, a negative error code on failure.
 */
int scion_build_paths(scion_ia src, scion_ia dst, struct scion_topology *topology, struct scion_path_segment **ups,
	size_t ups_length, struct scion_path_segment **cores, size_t cores_length, struct scion_path_segment **downs,
	size_t downs_length, struct scion_linked_list *paths, uint opt);
