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

#include <endian.h>
#include <stdbool.h>

#define SCION_MAC_LEN 6
#define SCION_HOP_LEN 12

// Documentation mostly taken from:
// https://github.com/scionproto/scion/blob/master/pkg/slayers/path/hopfield.go

// The Hop Field has the following format:
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|r r r r r r I E|    ExpTime    |           ConsIngress         |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|        ConsEgress             |                               |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
//	|                              MAC                              |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

struct scion_hop_field {
	// IngressRouterAlert flag. If the IngressRouterAlert is set, the ingress router (in
	// construction direction) will process the L4 payload in the packet.
	bool ingress_router_alert;
	// EgressRouterAlert flag. If the EgressRouterAlert is set, the egress router (in
	// construction direction) will process the L4 payload in the packet.
	bool egress_router_alert;
	// Exptime is the expiry time of a scion_hop_field. The field is 1-byte long, thus there are 256
	// different values available to express an expiration time. The expiration time expressed by
	// the value of this field is relative, and an absolute expiration time in seconds is computed
	// in combination with the timestamp field (from the corresponding info field) as follows
	//
	// Timestamp + (1 + ExpTime) * (24*60*60)/256
	uint8_t exp_time;
	// ConsIngress is the ingress interface ID in construction direction.
	uint16_t cons_ingress;
	// ConsEgress is the egress interface ID in construction direction.
	uint16_t cons_egress;
	// Mac is the 6-byte Message Authentication Code to authenticate the scion_hop_field.
	char mac[6];
};

int scion_hop_field_serialize(uint8_t *buf, struct scion_hop_field *hop_field);

int scion_hop_field_deserialize(uint8_t *buf, struct scion_hop_field *hop_field);
