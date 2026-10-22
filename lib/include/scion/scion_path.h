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
 * @file scion_path.h
 *
 * The path API of the csnet library.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <math.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

#include <scion/scion.h>

/**
 * @struct scion_path
 *
 * @brief A SCION path.
 */
struct scion_path;

/**
 * Reverses a path.
 * @param[in,out] path The path to reverse.
 * @return 0 on success, a negative error code on failure.
 */
int scion_path_reverse(struct scion_path *path);

/**
 * Gets the number of hops of a path.
 * @param[in] path The path.
 * @return The number of hops of the path.
 */
size_t scion_path_get_numhops(const struct scion_path *path);

/**
 * Makes the border router of one interface of a path process the SCMP message sent along the path.
 *
 * The router alert flag of the hop field that belongs to the interface is set and the flag of every other hop field is
 * cleared. A border router that sees the flag answers a traceroute request, see @ref scion_scmp_traceroute.
 * @param[in,out] path The path.
 * @param[in] interface_index The index into the interfaces of the path metadata, 0 is the first one of the source AS.
 * @return 0 on success, a negative error code on failure.
 *
 * @note Fails with @c SCION_ERR_PATH_TYPE_INVALID for a path without hops, and with @c SCION_ERR_INDEX_OUT_OF_RANGE if
 * the path has no such interface.
 * @note Reversing the path invalidates the index.
 */
int scion_path_set_router_alert(struct scion_path *path, size_t interface_index);

/**
 * Frees a path.
 * @param[in] path The path to free.
 */
void scion_path_free(struct scion_path *path);

/**
 * Returns true if the latency is unknown.
 * @param latency The latency.
 */
#define SCION_PATH_METADATA_LATENCY_IS_UNSET(latency) (latency.tv_sec == 0 && latency.tv_usec == -1)
/**
 * Returns true if the bandwidth is unknown.
 * @param bandwidth The bandwidth.
 */
#define SCION_PATH_METADATA_BANDWIDTH_IS_UNSET(bandwidth) (bandwidth == 0)
/**
 * Returns true if the geographical location is unknown.
 * @param geo The geographical location.
 */
#define SCION_PATH_METADATA_GEO_IS_UNSET(geo) (isnan(geo.latitude) && isnan(geo.longitude) && geo.address == NULL)
/**
 * Returns true if the number of internal hops is unknown.
 * @param internal_hops The number of internal hops.
 */
#define SCION_PATH_METADATA_INTERNAL_HOPS_IS_UNSET(internal_hops) (internal_hops == 0)

/**
 * @struct scion_path_interface
 *
 * @brief An interface of an AS in a SCION path.
 */
struct scion_path_interface {
	/**
	 * The identifier of the interface.
	 */
	scion_ifid id;
	/**
	 * The AS identifier.
	 */
	scion_ia ia;
};

/**
 * @struct scion_geo_coordinates
 *
 * @brief The geographic location of an AS.
 */
struct scion_geo_coordinates {
	/**
	 * Latitude of the geographic coordinate, in the WGS 84 datum.
	 */
	float latitude;
	/**
	 * Longitude of the geographic coordinate, in the WGS 84 datum.
	 */
	float longitude;
	/**
	 * Civic address of the location.
	 */
	char *address;
};

/**
 * The linky type of a hop.
 */
enum scion_link_type {
	/**
	 * Unspecified link type.
	 */
	SCION_LINK_TYPE_UNSPECIFIED = 0,
	/**
	 * Direct physical connection.
	 */
	SCION_LINK_TYPE_DIRECT = 1,
	/**
	 * Connection with local routing/switching.
	 */
	SCION_LINK_TYPE_MULTI_HOP = 2,
	/**
	 * Connection overlaid over publicly routed Internet.
	 */
	SCION_LINK_TYPE_OPEN_NET = 3
};

/**
 * @struct scion_path_metadata
 *
 * @brief The metadata of a SCION path.
 */
struct scion_path_metadata {
	/**
	 * All ASes on the path.
	 */
	scion_ia *ases;
	size_t ases_len;

	/**
	 * All interfaces on the path.
	 */
	struct scion_path_interface *interfaces;
	size_t interfaces_len;

	/**
	 * Maximum transmission unit for the path, in bytes.
	 */
	uint32_t mtu;
	/**
	 * Expiration time of the path.
	 */
	int64_t expiry;

	/**
	 * List of latencies between any two consecutive interfaces.
	 * Entry i describes the latency between interface i and i+1.
	 * Consequently, there are N-1 entries for N interfaces.
	 * SCION_PATH_METADATA_LATENCY_IS_UNSET can be used to check whether an entry is set or not.
	 */
	struct timeval *latencies;

	/**
	 * List of bandwidths between any two consecutive interfaces, in Kbit/s.
	 * Entry i describes the bandwidth between interfaces i and i+1.
	 * A 0-value indicates that the AS did not announce a bandwidth for this hop.
	 * SCION_PATH_METADATA_BANDWIDTH_IS_UNSET can be used to check whether an entry is set or not.
	 */
	uint64_t *bandwidths;

	/**
	 * Geographical positions of the border routers along the path.
	 * Entry i describes the position of the router for interface i.
	 * A 0-value indicates that the AS did not announce a position for this router.
	 * SCION_PATH_METADATA_GEO_IS_UNSET can be used to check whether an entry is set or not.
	 */
	struct scion_geo_coordinates *geo;

	/**
	 * Link types of inter-domain links.
	 * Entry i describes the link between interfaces 2*i and 2*i+1.
	 */
	enum scion_link_type *link_types;

	//
	/**
	 * Numbers of AS internal hops for the ASes on path.
	 * Entry i describes the hop between interfaces 2*i+1 and 2*i+2 in the same AS.
	 * Consequently, there are no entries for the first and last ASes, as these
	 * are not traversed completely by the path.
	 * SCION_PATH_METADATA_INTERNAL_HOPS_IS_UNSET can be used to check whether an entry is set or not.
	 */
	uint32_t *internal_hops;

	/**
	 * Notes added by ASes on the path, in the order of occurrence.
	 * Entry i is the note of AS i on the path.
	 */
	char **notes;
};

/**
 * Gets the metadata of a path.
 * @param[in] path The path.
 * @return A reference to the metadata of the path.
 *
 * @note Do not modify the metadata.
 */
const struct scion_path_metadata *scion_path_get_metadata(const struct scion_path *path);

/**
 * Prints a path to stdout.
 * @param[in] path The path to print.
 */
void scion_path_print(const struct scion_path *path);

/**
 * Prints the metadata of a path.
 * @param[in] path The path.
 */
void scion_path_print_metadata(const struct scion_path *path);

/**
 * @struct scion_path_collection
 *
 * @brief A collection of SCION paths.
 */
struct scion_path_collection;

/**
 * A function that matches a path with a custom context.
 * @param path The candidate path.
 * @param ctx The custom context.
 * @return true, if the path matches the predicate
 * @return false, if the path does not match the predicate
 */
typedef bool (*scion_path_predicate_fn)(struct scion_path *path, void *ctx);

/**
 * @struct scion_path_predicate
 *
 * @brief A path predicate.
 */
struct scion_path_predicate {
	/**
	 * The predicate function.
	 */
	scion_path_predicate_fn fn;
	/**
	 * The user-defined context that will be provided to the predicate function. Can be NULL.
	 */
	void *ctx;
};

/**
 * A function that compares two paths with a custom context.
 * @param path_one The first path.
 * @param path_two The second path.
 * @param ctx The custom context.
 * @return 1, if path_one > path_two
 * @return 0, if path_one == path_two
 * @return -1, if path_one < path_two
 */
typedef int (*scion_path_comparator_fn)(struct scion_path *path_one, struct scion_path *path_two, void *ctx);

/**
 * @struct scion_path_comparator
 *
 * @brief A path comparator.
 */
struct scion_path_comparator {
	/**
	 * The comparator function.
	 */
	scion_path_comparator_fn fn;
	/**
	 * The user-defined context that will be provided to the comparator function. Can be NULL.
	 */
	void *ctx;
	/**
	 * The sorting order.
	 */
	bool ascending;
};

/**
 * Frees a collection of paths, including the paths themselves.
 * @param[in] paths The path collection.
 */
void scion_path_collection_free(struct scion_path_collection *paths);

/**
 * Finds the first path that matches the provided predicate.
 * @param[in] paths The path collection.
 * @param[in] predicate The predicate.
 * @return The first path that matches, or NULL if no path matched.
 *
 * @see @link scion_path_predicate @endlink
 */
struct scion_path *scion_path_collection_find(
	struct scion_path_collection *paths, struct scion_path_predicate predicate);

/**
 * Gets and removes the first element from a path collection.
 * @param[in] paths The path collection.
 * @return The first element of the path collection, or NULL if the path collection is empty.
 *
 * @note The returned element must be freed by the caller.
 */
struct scion_path *scion_path_collection_pop(struct scion_path_collection *paths);

/**
 * Gets the first element of a path collection.
 * @param[in] paths The path collection.
 * @return The first element of the path collection, or NULL if the path collection is empty.
 *
 * @note The returned element must not be freed by the caller.
 */
struct scion_path *scion_path_collection_first(struct scion_path_collection *paths);

/**
 * Sorts a path collection in-place with the provided comparator.
 * @param[in,out] paths The path collection.
 * @param[in] comparator The comparator.
 *
 * @see @link scion_path_comparator @endlink
 */
void scion_path_collection_sort(struct scion_path_collection *paths, struct scion_path_comparator comparator);

/**
 * Filters a path collection in-place with the provided predicate.
 * @param[in,out] paths The path collection.
 * @param[in] predicate The predicate.
 *
 * @see @link scion_path_predicate @endlink
 */
void scion_path_collection_filter(struct scion_path_collection *paths, struct scion_path_predicate predicate);

/**
 * Gets the number of paths in a path collection.
 * @param[in] paths The path collection.
 * @return The number of paths in the path collection.
 */
size_t scion_path_collection_size(struct scion_path_collection *paths);

/**
 * Creates an array representation of a path collection.
 * @param[in] paths The path collection.
 * @param[out] len The length of the array.
 * @return The array representation of the path collection.
 *
 * @note The array must be freed by the caller. Do not free the path entries.
 */
struct scion_path **scion_path_collection_as_array(struct scion_path_collection *paths, size_t *len);

/**
 * Prints a path collection to stdout, grouped by the number of hops. For example:
 * @code
 * Available paths:
 * 3 Hops:
 * [0]:  Hops: [1-ff00:0:111 42>2 1-ff00:0:110 3>51 1-ff00:0:112] MTU: 1280
 * [1]:  Hops: [1-ff00:0:111 42>2 1-ff00:0:110 4>52 1-ff00:0:112] MTU: 1280
 * [2]:  Hops: [1-ff00:0:111 41>1 1-ff00:0:110 3>51 1-ff00:0:112] MTU: 1280
 * [3]:  Hops: [1-ff00:0:111 41>1 1-ff00:0:110 4>52 1-ff00:0:112] MTU: 1280
 * @endcode
 * @param[in] paths The path list to print.
 */
void scion_path_collection_print(struct scion_path_collection *paths);

/**
 * Fetches the paths from the local SCION network to the destination IA.
 * @param[in] network The local network.
 * @param[in] dst The destination IA.
 * @param[in] opt Optional path finding options.
 * @param[out] paths The collection of paths found.
 * @return 0 on success, a negative error code on failure.
 */
int scion_path_collection_fetch(
	struct scion_network *network, scion_ia dst, unsigned int opt, struct scion_path_collection **paths);

#ifdef __cplusplus
}
#endif
