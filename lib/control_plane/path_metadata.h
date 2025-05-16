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
#include "util/linked_list.h"

#define SCION_PATH_METADATA_LATENCY_IS_UNSET(latency) (latency.tv_sec == 0 && latency.tv_usec == -1)
#define SCION_PATH_METADATA_BANDWIDTH_IS_UNSET(bandwidth) (bandwidth == 0)
#define SCION_PATH_METADATA_GEO_IS_UNSET(geo) (geo.latitude == NAN && geo.longitude == NAN && geo.address == NULL)
#define SCION_PATH_METADATA_INTERNAL_HOPS_UNSET(internal_hops) (internal_hops == 0)

typedef uint64_t scion_interface_id;

struct scion_path_interface {
	scion_interface_id id;
	scion_ia ia;
};

struct scion_geo_coordinates {
	// Latitude of the geographic coordinate, in the WGS 84 datum.
	float latitude;
	// Longitude of the geographic coordinate, in the WGS 84 datum.
	float longitude;
	// Civic address of the location.
	char *address;
};

enum scion_link_type {
	// Unspecified link type.
	SCION_LINK_TYPE_UNSPECIFIED = 0,
	// Direct physical connection.
	SCION_LINK_TYPE_DIRECT = 1,
	// Connection with local routing/switching.
	SCION_LINK_TYPE_MULTI_HOP = 2,
	// Connection overlayed over publicly routed Internet.
	SCION_LINK_TYPE_OPEN_NET = 3
};

struct scion_path_metadata {
	// List of ASes on the path
	struct scion_linked_list *as_numbers;
	// List of interfaces on the path.
	struct scion_linked_list *interfaces;

	// Maximum transmission unit for the path, in bytes.
	uint32_t mtu;
	// Expiration time of the path.
	int64_t expiry;

	// List of latencies between any two consecutive interfaces.
	// Entry i describes the latency between interface i and i+1.
	// Consequently, there are N-1 entries for N interfaces.
	// A negative value (LatencyUnset) indicates that the AS did not announce a
	// latency for this hop.
	struct timeval *latencies;

	// List of bandwidths between any two consecutive interfaces, in Kbit/s.
	// Entry i describes the bandwidth between interfaces i and i+1.
	// A 0-value indicates that the AS did not announce a bandwidth for this hop.
	uint64_t *bandwidths;

	// Geographical positions of the border routers along the path.
	// Entry i describes the position of the router for interface i.
	// A 0-value indicates that the AS did not announce a position for this router.
	struct scion_geo_coordinates *geo;

	// Link types of inter-domain links.
	// Entry i describes the link between interfaces 2*i and 2*i+1.
	enum scion_link_type *link_types;

	// Numbers of AS internal hops for the ASes on path.
	// Entry i describes the hop between interfaces 2*i+1 and 2*i+2 in the same AS.
	// Consequently, there are no entries for the first and last ASes, as these
	// are not traversed completely by the path.
	uint32_t *internal_hops;

	// Notes added by ASes on the path, in the order of occurrence.
	// Entry i is the note of AS i on the path.
	char **notes;
};

void scion_geo_coordinates_free(struct scion_geo_coordinates *geo);

void scion_path_metadata_free(struct scion_path_metadata *path_meta);

struct scion_path_metadata *scion_path_metadata_collect(
	struct scion_linked_list *interfaces, struct scion_linked_list *as_entries, uint32_t mtu, int64_t expiry);

void scion_path_metadata_print(struct scion_path_metadata *path_meta);
