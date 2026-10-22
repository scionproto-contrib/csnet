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

#include <math.h>
#include <stdint.h>

#include "common/isd_as.h"
#include "scion/scion.h"
#include "scion/scion_path.h"
#include "util/list.h"

/**
 * Frees geographical coordinates and their address.
 * @param[in] geo The geographical coordinates, can be NULL.
 */
void scion_geo_coordinates_free(struct scion_geo_coordinates *geo);

/**
 * Frees path metadata and everything it owns.
 * @param[in] path_meta The path metadata, can be NULL.
 */
void scion_path_metadata_free(struct scion_path_metadata *path_meta);

/**
 * Collects the metadata of a path.
 * @param[in] interfaces The interfaces of the path as a list of struct scion_path_interface, in pairs of the interface
 * the path leaves an AS at and the interface it enters the next AS at. Must not be empty.
 * @param[in] as_entries The AS entries of the path segments as a list of struct scion_as_entry. Their static
 * information provides the latencies, bandwidths, geographical coordinates, link types, internal hops and notes.
 * @param[in] mtu The MTU of the path.
 * @param[in] expiry The expiry time of the path as a Unix timestamp in seconds.
 * @return The path metadata, which has to be freed with scion_path_metadata_free().
 */
struct scion_path_metadata *scion_path_metadata_collect(
	struct scion_list *interfaces, struct scion_list *as_entries, uint32_t mtu, int64_t expiry);

/**
 * Prints path metadata to stdout.
 * @param[in] path_meta The path metadata. If NULL, a message that there is no metadata is printed.
 */
void scion_path_metadata_print(struct scion_path_metadata *path_meta);
