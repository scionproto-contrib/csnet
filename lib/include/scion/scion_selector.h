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
 * @file scion_selector.h
 *
 * The path selector API of the csnet library.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <scion/scion.h>
#include <scion/scion_path.h>

/**
 * A function that chooses the path for the next packet of a connected socket. The socket calls it for every packet
 * that it sends.
 * @param[in] paths The paths of the socket that the path policy allows, the most preferred first. The paths are
 * borrowed, the function must not free or modify the collection.
 * @param[in] current The path that was used for the previous packet, or NULL if there was none or if it is not
 * available anymore.
 * @param[in] ctx The user-defined context that was provided when creating the selector.
 * @return One of the paths of the collection, or NULL if the packet cannot be sent. The path must not be used after the
 * next call of the function, because the paths are replaced when they are refreshed.
 *
 * @see @link scion_path_is_down @endlink
 */
typedef struct scion_path *(*scion_selector_fn)(
	struct scion_path_collection *paths, const struct scion_path *current, void *ctx);

/**
 * A SCION path selector. It chooses which of the allowed paths a connected socket uses, in contrast to the path policy
 * that decides which paths are allowed.
 */
struct scion_selector {
	/**
	 * The function that implements the path selector.
	 */
	scion_selector_fn fn;

	/**
	 * The user-defined context that will be provided to every path selector function invocation. Not owned.
	 */
	void *ctx;
};

#ifdef __cplusplus
}
#endif
