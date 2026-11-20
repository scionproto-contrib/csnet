// Copyright 2026 ETH Zurich
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

// The TRCs of a network, and the certificate chains that are verified against them.

#pragma once

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "control_plane/pki/cert_chain.h"

struct scion_network;

/*
 * The TRCs of a network. A network is shared between threads, so the TRCs are only accessed with the lock held.
 */
struct scion_trc_store {
	pthread_mutex_t lock;
	struct scion_trc *trcs;
	size_t num_trcs;
};

/*
 * Whether a network has a TRC to verify the control plane with.
 */
bool scion_network_has_trcs(const struct scion_network *net);

/*
 * Verifies a certificate chain against the TRCs of its ISD that are active at a time: the latest TRC, and in its grace
 * period the TRC before it. Returns SCION_ERR_CERT_CHAIN_UNVERIFIED if the chain cannot be verified, also if the
 * network has no active TRC of the ISD.
 */
int scion_network_verify_chain(const struct scion_network *net, struct scion_cert_chain *chain, time_t now);

/*
 * Fetches the certificate chains of an AS with a subject key ID from the control service, and returns the first one
 * that the network verifies at a time. Returns SCION_ERR_CERT_CHAIN_UNVERIFIED if none of them can be verified.
 */
int scion_network_fetch_chain(const struct scion_network *net, scion_ia ia, const uint8_t *subject_key_id,
	size_t subject_key_id_len, time_t now, struct scion_cert_chain *chain);

/*
 * Updates the TRCs of an ISD up to a TRC, as far as the network does not have it: fetches the TRCs after the latest TRC
 * of the ISD from the control service, and adds each that is valid at a time and an update of the TRC before it.
 * Returns SCION_ERR_TRC_INVALID if a TRC is not such an update, also if the network has no TRC of the ISD with the
 * same base number.
 */
int scion_network_update_trcs(
	const struct scion_network *net, scion_isd isd, uint64_t base, uint64_t serial, time_t now);

/*
 * Frees the TRCs of a network, after which the network has no TRCs.
 */
void scion_network_free_trcs(struct scion_network *net);
