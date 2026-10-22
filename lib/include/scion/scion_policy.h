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

/**
 * @file scion_policy.h
 *
 * The path policy API of the csnet library.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include <scion/scion.h>
#include <scion/scion_path.h>

/**
 * A function that implements the path selection policy by filtering and/or sorting the available paths contained
 * in the path collection. The function must modify the path collection in-place. When sorting the paths, the most
 * preferred path should be the first path.
 * @param[in,out] paths The path collection.
 * @param[in] ctx The user-defined context that was provided when creating the policy.
 *
 * @see @link scion_path_collection_filter @endlink, @link scion_path_collection_sort @endlink
 */
typedef void (*scion_policy_fn)(struct scion_path_collection *paths, void *ctx);

/**
 * A SCION path policy.
 */
struct scion_policy {
	/**
	 * The function that implements the path policy.
	 */
	scion_policy_fn fn;

	/**
	 * The user-defined context that will be provided to every path policy function invocation.
	 */
	void *ctx;
};

/**
 * A policy that prefers paths with high MTU.
 */
extern const struct scion_policy scion_policy_highest_mtu;

/**
 * A policy that prefers paths with few hops.
 */
extern const struct scion_policy scion_policy_least_hops;

/**
 * A policy that prefers paths with low latency.
 */
extern const struct scion_policy scion_policy_lowest_latency;

/**
 * A policy that prefers paths with high bandwidth.
 */
extern const struct scion_policy scion_policy_highest_bandwidth;

/**
 * Returns a policy that ensures all paths have the provided minimum MTU.
 * @param[in] mtu The minimum MTU.
 * @return The path policy.
 */
struct scion_policy scion_policy_min_mtu(uint32_t *mtu);

/**
 * Sets the path selection policy of a socket.
 * @param scion_sock The socket.
 * @param policy The path selection policy to use.
 * @return 0 on success, a negative error code on failure.
 */
int scion_setsockpolicy(struct scion_socket *scion_sock, struct scion_policy policy);

#ifdef __cplusplus
}
#endif
