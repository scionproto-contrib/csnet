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

#include <stdint.h>

#include "common/hop_field.h"
#include "common/isd_as.h"

struct scion_latency_info {
	struct scion_map *intra;
	struct scion_map *inter;
};

struct scion_bandwidth_info {
	struct scion_map *intra;
	struct scion_map *inter;
};

struct scion_static_info_extension {
	struct scion_latency_info *latency;
	struct scion_bandwidth_info *bandwidth;
	struct scion_map *geo;
	struct scion_map *link_type;
	struct scion_map *internal_hops;
	char *note;
};

struct scion_path_segment_extensions {
	struct scion_static_info_extension *static_info;

	// TODO add other extensions
};

struct scion_hop_entry {
	// hop_field contains the necessary information to create a data-plane hop.
	struct scion_hop_field hop_field;
	// IngressMTU is the MTU on the ingress link.
	uint16_t ingress_mtu;
};

struct scion_peer_entry {
	// HopField contains the necessary information to create a data-plane hop.
	struct scion_hop_field hopfield;
	// Peer is the ISD-AS of the peering AS.
	scion_ia peer;
	// PeerInterface is the interface ID of the peering link on the remote
	// peering AS side.
	uint16_t peer_interface;
	// PeerMTU is the MTU on the peering link.
	uint16_t peer_mtu;
};

struct scion_as_entry {
	// TODO add field for signed ASEntry
	// local is the ISD-AS of the AS correspoding to this entry.
	scion_ia local;
	// next is the ISD-AS of the downstream AS.
	scion_ia next;
	// HopEntry is the entry to create regular data plane paths.
	struct scion_hop_entry hop_entry;
	// peer_entries_length is the number of peer entries in the peer_entries list.
	uint16_t peer_entries_length;
	// peer_entries is a list of entries to create peering data plane paths.
	struct scion_peer_entry **peer_entries;
	// mtu is the AS internal MTU.
	uint16_t mtu;

	// Optional extensions.
	struct scion_path_segment_extensions extensions;
	// TODO add unsigned extensions
};

void scion_as_entry_free(struct scion_as_entry *as_entry);

size_t scion_as_entry_byte_size(struct scion_as_entry *as_entry);
