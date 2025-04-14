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

#include "scion/common/isd_as.h"
#include "scion/common/path_collection.h"
#include "scion/control_plane/network.h"

#define SCION_FETCH_OPT_DEBUG 1

/*
 * FUNCTION: scion_fetch_paths
 * -----------------
 * Returns a list of available paths between a SCION network and a given destination AS by
 * fetching the required path segments from the local Control Server.
 *
 * Arguments:
 *      - struct scion_network *network: Pointer to the SCION network.
 *      - ScionIA dst: destination AS.
 *      - struct scion_linked_list *paths: Pointer to a scion_linked_list into which the resulting scion_path structs,
 *        which represent the available paths, will be stored.
 *
 * Returns:
 *      - An integer status code, 0 for success or an error code as defined in error.h.
 */
int scion_fetch_paths(struct scion_network *network, scion_ia dst, uint opt, struct scion_path_collection **paths);
