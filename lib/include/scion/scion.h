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

/**
 * @file scion.h
 *
 * The CSNET library.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/time.h>

#define SCION_SO_DEBUG 200

#define SCION_FETCH_OPT_DEBUG 1

/**
 * Possible error codes returned by the CSNET library.
 *
 * Errors codes smaller than -200 are internal error codes.
 */
enum scion_error {
	/**
	 * Something went wrong.
	 */
	SCION_ERR_GENERIC = -1,
	/**
	 * Memory allocation failed.
	 */
	SCION_ERR_MEM_ALLOC_FAIL = -2,
	/**
	 * No paths to the destination were found.
	 */
	SCION_ERR_NO_PATHS = -3,
	/**
	 * The buffer provided was not large enough.
	 */
	SCION_ERR_BUF_TOO_SMALL = -4,
	/**
	 * Encountered an unsupported address family.
	 *
	 * @see @link scion_addr_family @endlink
	 */
	SCION_ERR_ADDR_FAMILY_UNKNOWN = -5,
	/**
	 * Could not send the packet because the maximum SCION header length was exceeded.
	 */
	SCION_ERR_MAX_HDR_LEN_EXCEEDED = -6,
	/**
	 * The file provided was not found.
	 */
	SCION_ERR_FILE_NOT_FOUND = -7,
	/**
	 * The topology is invalid.
	 */
	SCION_ERR_TOPOLOGY_INVALID = -8,
	/**
	 * The provided address has an incompatible address family.
	 * This can happen when binding an address that has a different address family than the socket, or when
	 * sending/connecting to a host in the same AS that has a different address family than the socket.
	 */
	SCION_ERR_ADDR_FAMILY_MISMATCH = -9,
	/**
	 * The provided network has a different address family than the socket.
	 */
	SCION_ERR_NETWORK_ADDR_FAMILY_MISMATCH = -10,
	/**
	 * The protocol is not supported.
	 *
	 * @see @link scion_proto @endlink
	 */
	SCION_ERR_PROTO_UNKNOWN = -11,
	/**
	 * The socket is not connected yet.
	 */
	SCION_ERR_NOT_CONNECTED = -12,
	/**
	 * The path destination IA does not match the destination IA.
	 */
	SCION_ERR_DST_MISMATCH = -13,
	/**
	 * The provided IA string is invalid.
	 */
	SCION_ERR_INVALID_ISD_AS_STR = -14,
	/**
	 * The receive operation is in non-blocking mode and there is nothing to receive.
	 */
	SCION_ERR_WOULD_BLOCK = -15,
	/**
	 * The provided address is invalid.
	 */
	SCION_ERR_ADDR_INVALID = -16,
	/**
	 * The socket is already bound.
	 */
	SCION_ERR_ALREADY_BOUND = -17,
	/**
	 * The flag is not implemented by the library.
	 */
	SCION_ERR_FLAG_NOT_IMPLEMENTED = -18,
	/**
	 * The flag is not supported by the OS.
	 */
	SCION_ERR_FLAG_NOT_SUPPORTED = -19,
	/**
	 * Encountered an unexpected error when sending packets.
	 */
	SCION_ERR_SEND_FAIL = -20,
	/**
	 * Encountered an unexpected error when receiving packets.
	 */
	SCION_ERR_RECV_FAIL = -21,
	/**
	 * The address is already in use.
	 *
	 * @see [EADDRINUSE](https://man7.org/linux/man-pages/man7/ip.7.html#ERRORS)
	 */
	SCION_ERR_ADDR_IN_USE = -22,
	/**
	 * The address is not available.
	 *
	 * @see [EADDRNOTAVAIL](https://man7.org/linux/man-pages/man7/ip.7.html#ERRORS)
	 */
	SCION_ERR_ADDR_NOT_AVAILABLE = -23,
	/**
	 * The socket output queue is already full.
	 *
	 * @see [ENOBUFS](https://man7.org/linux/man-pages/man7/ip.7.html#ERRORS)
	 */
	SCION_ERR_OUTPUT_QUEUE_FULL = -24,
	/**
	 * The provided socket option is invalid.
	 */
	SCION_ERR_SOCK_OPT_INVALID = -25,
	/**
	 * The provided address buffer is too small.
	 */
	SCION_ERR_ADDR_BUF_TOO_SMALL = -26,
	/**
	 * The path has expired and needs to be refreshed.
	 */
	SCION_ERR_PATH_EXPIRED = -27,
	/**
	 * The socket is not bound.
	 */
	SCION_ERR_NOT_BOUND = -28,
	/**
	 * Operation cannot be performed with a networkless socket.
	 */
	SCION_ERR_NETWORK_UNKNOWN = -29,
	/**
	 * The message is too large.
	 */
	SCION_ERR_MSG_TOO_LARGE = -30,
	/**
	 * The source address of the socket could not automatically be determined. It has to be provided by
	 * explicitly binding the socket to a non-wildcard address.
	 *
	 * @see [Source Address Determination](docs/design/source_address_determination.md)
	 */
	SCION_ERR_SRC_ADDR_UNKNOWN = -31,
	// Internal errors
	SCION_ERR_NOT_ENOUGH_DATA = -201,
	SCION_ERR_PACKET_FIELD_INVALID = -202,
	SCION_ERR_GRPC_FAIL = -203,
	SCION_ERR_META_HDR_INVALID = -204,
	SCION_ERR_PATH_TYPE_INVALID = -205,
	SCION_ERR_SCMP_CODE_INVALID = -206,
};

/**
 * Returns the string representation of an error.
 * @param err A SCION error.
 * @return A string representation of the error.
 */
char *scion_strerror(int err);

/**
 * The address families that SCION supports.
 */
enum scion_addr_family {
	/**
	 * IPv4 addresses.
	 */
	SCION_AF_INET = AF_INET,
	/**
	 * IPv6 addresses.
	 */
	SCION_AF_INET6 = AF_INET6
};

/**
 * The protocols that SCION supports.
 */
enum scion_proto {
	/**
	 * User Datagram Protocol
	 * @see https://en.wikipedia.org/wiki/User_Datagram_Protocol
	 */
	SCION_PROTO_UDP = 17,
	/**
	 * SCION Control Message Protocol
	 * @see https://docs.scion.org/en/latest/protocols/scmp.html
	 */
	SCION_PROTO_SCMP = 202
};

/**
 * A fully qualified AS identifier called IA.
 */
typedef uint64_t scion_ia;

/**
 * Parses an IA string.
 * @param[in] str The string.
 * @param[in] len The length of the string (without NULL terminator).
 * @param[out] ia The resulting IA.
 * @return 0 on success, a negative error code on failure.
 */
int scion_ia_parse(const char *str, size_t len, scion_ia *ia);

/**
 * Prints an IA to stdout.
 * @param[in] ia The IA.
 */
void scion_ia_print(scion_ia ia);

/**
 * @struct scion_topology
 *
 * @brief A topology context in SCION.
 *
 * Contains information about how to reach the SCION infrastructure.
 */
struct scion_topology;

/**
 * Initializes a topology from a file.
 * @param[out] topology The resulting topology.
 * @param[in] path The path of the topology file.
 * @return 0 on success, a negative error code on failure.
 */
int scion_topology_from_file(struct scion_topology **topology, const char *path);

/**
 * Gets the IA from the topology.
 * @param[in] topo The topology.
 * @return The IA of the topology.
 */
scion_ia scion_topology_get_local_ia(struct scion_topology *topo);

/**
 * Frees a topology.
 * @param[in] topo The topology to free.
 */
void scion_topology_free(struct scion_topology *topo);

/**
 * @struct scion_network
 *
 * @brief A network context in SCION.
 *
 * Contains information about the local SCION network. It can be used to open a new SCION socket or to fetch
 * paths.
 */
struct scion_network;

/**
 * Initializes a network with a topology.
 * @param[out] net The resulting network.
 * @param[in] topology The topology of the network.
 * @return 0 on success, a negative error code on failure.
 */
int scion_network(struct scion_network **net, struct scion_topology *topology);

/**
 * Frees a network.
 * @param[in] net The network to free.
 */
void scion_network_free(struct scion_network *net);

/**
 * Gets the local address family of a network.
 * @param[in] net The network.
 * @return The local address family.
 */
enum scion_addr_family scion_network_get_local_addr_family(struct scion_network *net);

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
size_t scion_path_get_hops(const struct scion_path *path);

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
#define SCION_PATH_METADATA_GEO_IS_UNSET(geo) (geo.latitude == NAN && geo.longitude == NAN && geo.address == NULL)
/**
 * Returns true if the number of internal hops is unknown.
 * @param internal_hops The number of internal hops.
 */
#define SCION_PATH_METADATA_INTERNAL_HOPS_IS_UNSET(internal_hops) (internal_hops == 0)

/**
 * An interface identifier.
 */
typedef uint64_t scion_interface_id;

/**
 * @struct scion_path_interface
 *
 * @brief An interface of an AS in a SCION path.
 */
struct scion_path_interface {
	/**
	 * The identifier of the interface.
	 */
	scion_interface_id id;
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
 * Prints a path collection to stdout.
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
int scion_fetch_paths(struct scion_network *network, scion_ia dst, uint opt, struct scion_path_collection **paths);

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
 * @struct scion_socket
 *
 * @brief A SCION socket.
 */
struct scion_socket;

/**
 * A callback for SCMP error handling.
 * @param buf The buffer containing the SCMP error message.
 * @param size The size of the buffer.
 * @param ctx The context that was provided when setting up the callback.
 *
 * @see @link scion_setsockerrcb @endlink
 */
typedef void scion_socket_scmp_error_cb(uint8_t *buf, size_t size, void *ctx);

/**
 * Initializes a SCION socket.
 * @param[out] scion_sock The resulting SCION socket.
 * @param[in] addr_family The address family to use.
 * @param[in] protocol The protocol to use.
 * @param[in] network The network to use. If NULL, the socket is in networkless mode. Networkless sockets cannot be
 * connected, must always be bound manually before sending and always need an explicit path when sending.
 * @return 0 on success, a negative error code on failure.
 */
int scion_socket(struct scion_socket **scion_sock, enum scion_addr_family addr_family, enum scion_proto protocol,
	struct scion_network *network);

/**
 * Binds a SCION socket to an address.
 * @param[in,out] scion_sock The socket to bind.
 * @param[in] addr The address to bind.
 * @param[in] addrlen The length of the address.
 * @return 0 on success, a negative error code on failure.
 */
int scion_bind(struct scion_socket *scion_sock, const struct sockaddr *addr, socklen_t addrlen);

/**
 * Connects a SCION socket to an address.
 * @param[in,out] scion_sock The socket to connect.
 * @param[in] addr The address to connect to.
 * @param[in] addrlen The length of the address.
 * @param[in] ia The IA to connect to.
 * @return 0 on success, a negative error code on failure.
 *
 * @note Cannot be used with networkless sockets.
 */
int scion_connect(struct scion_socket *scion_sock, const struct sockaddr *addr, socklen_t addrlen, scion_ia ia);

/**
 * Sends a packet to the connected destination of the SCION socket.
 * @param[in,out] scion_sock The connected socket to use.
 * @param[in] buf The data to send.
 * @param[in] size The size of the data.
 * @param[in] flags The send flags to use. Must be 0 if no flags should be used.
 * @return The amount of data sent on success, a negative error code on failure.
 *
 * @note The currently supported send flags are MSG_CONFIRM, MSG_DONTWAIT and MSG_MORE.
 * @note Is equivalent to scion_sendto(scion_sock, buf, size, flags, NULL, 0, 0, NULL).
 */
ssize_t scion_send(struct scion_socket *scion_sock, const void *buf, size_t size, int flags);

/**
 * Sends a packet to a destination.
 * @param[in,out] scion_sock The socket.
 * @param[in] buf The data to send.
 * @param[in] size The size of the data.
 * @param[in] flags The send flags to use. Must be 0 if no flags should be used.
 * @param[in] dst_addr The destination address. If NULL, the connected destination address is used.
 * @param[in] addrlen The length of the destination address. Must be 0 if dst_addr is NULL.
 * @param[in] dst_ia The destination IA. Must be 0 if dst_addr is NULL.
 * @param[in] path The path to use. If NULL, a suitable path is automatically used.
 * @return The amount of data sent on success, a negative error code on failure.
 *
 * @note The currently supported send flags are MSG_CONFIRM, MSG_DONTWAIT and MSG_MORE.
 * @note If a networkless socket is used, the path must be provided explicitly.
 */
ssize_t scion_sendto(struct scion_socket *scion_sock, const void *buf, size_t size, int flags,
	const struct sockaddr *dst_addr, socklen_t addrlen, scion_ia dst_ia, struct scion_path *path);

/**
 * Receives a packet on the SCION socket.
 * @param[in,out] scion_sock The socket.
 * @param[out] buf The buffer to store the received packet.
 * @param[in,out] size Must contain the size of the provided data buffer when calling. Contains the size of the data
 * received on return.
 * @param[in] flags The receive flags to use. Must be 0 if no flags should be used.
 * @return The amount of data received on success, a negative error code on failure.
 *
 * @note The currently supported receive flags are MSG_DONTWAIT and MSG_PEEK.
 * @note Is equivalent to scion_recvfrom(scion_sock, buf, size, flags, NULL, 0, 0, NULL).
 */
ssize_t scion_recv(struct scion_socket *scion_sock, void *buf, size_t size, int flags);

/**
 * Receives a packet on the SCION socket.
 * @param[in,out] scion_sock The socket.
 * @param[in] buf The buffer to store the received packet.
 * @param[in] size Must contain the size of the provided data buffer when calling. Contains the size of the data
 * received on return.
 * @param[in] flags The receive flags to use. Must be 0 if no flags should be used.
 * @param[out] src_addr The sender address of the packet. If NULL, the path is not returned.
 * @param[in,out] addrlen Must contain the size of the provided address buffer when calling. Contains the size of the
 * sender address on return.
 * @param[out] src_ia The sender IA. If NULL, the IA is not returned.
 * @param[out] path The path the packet took. If NULL, the path is not returned.
 * @return The amount of data received on success, a negative error code on failure.
 *
 * @note The currently supported receive flags are MSG_DONTWAIT and MSG_PEEK.
 */
ssize_t scion_recvfrom(struct scion_socket *scion_sock, void *buf, size_t size, int flags, struct sockaddr *src_addr,
	socklen_t *addrlen, scion_ia *src_ia, struct scion_path **path);

/**
 * Closes a SCION socket.
 * @param[in,out] scion_sock The socket to close.
 * @return 0 on success, a negative error code on failure.
 */
int scion_close(struct scion_socket *scion_sock);

/**
 * Gets a SCION socket option.
 * @param[in] scion_sock The socket.
 * @param[in] level The option level.
 * @param[in] optname The option name.
 * @param[out] optval The option value buffer.
 * @param[in,out] optlen Must contain the size of the option value buffer when calling. Contains the effective size of
 * the option value on return.
 * @return 0 on success, a negative error code on failure.
 *
 * @note Directly gets a socket option on the underlying system socket. Additionally, supports the socket level
 * option SCION_SO_DEBUG, which allows for better debugging.
 */
int scion_getsockopt(struct scion_socket *scion_sock, int level, int optname, void *optval, socklen_t *optlen);

/**
 * Sets a SCION socket option.
 * @param[in,out] scion_sock The socket.
 * @param[in] level The option level.
 * @param[in] optname The option name.
 * @param[in] optval The option value buffer.
 * @param[in] optlen The option value buffer length.
 * @return 0 on success, a negative error code on failure.
 *
 * @note Directly sets a socket option on the underlying system socket. Additionally, supports the socket level
 * option SCION_SO_DEBUG, which allows for better debugging.
 */
int scion_setsockopt(struct scion_socket *scion_sock, int level, int optname, const void *optval, socklen_t optlen);

/**
 * Gets the address of a SCION socket.
 * @param[in] scion_sock The socket.
 * @param[out] addr The address of the socket. If NULL, the address is not returned.
 * @param[in,out] addrlen Must contain the size of the address buffer when calling. Contains the effective size of the
 * address on return.
 * @param[out] ia The IA of the socket. If NULL, the IA is not returned.
 * @return 0 on success, a negative error code on failure.
 *
 * @note If a networkless socket is used, the IA must be NULL.
 */
int scion_getsockname(struct scion_socket *scion_sock, struct sockaddr *addr, socklen_t *addrlen, scion_ia *ia);

/**
 * Gets the file descriptor of the underlying system socket.
 * @param[in] scion_sock The socket.
 * @param[out] fd The file descriptor of the underlying system socket.
 * @return 0 on success, a negative error code on failure.
 */
int scion_getsockfd(struct scion_socket *scion_sock, int *fd);

/**
 * Sets the SCMP error callback that is called when a SCMP error is received by the socket.
 * @param[in,out] scion_sock The socket.
 * @param[in] cb The callback to use.
 * @param[in] ctx The user-defined context that is passed to every invocation of the callback. Can be NULL.
 * @return 0 on success, a negative error code on failure.
 */
int scion_setsockerrcb(struct scion_socket *scion_sock, scion_socket_scmp_error_cb cb, void *ctx);

/**
 * Sets the path selection policy of a socket.
 * @param scion_sock The socket.
 * @param policy The path selection policy to use.
 * @return 0 on success, a negative error code on failure.
 */
int scion_setsockpolicy(struct scion_socket *scion_sock, struct scion_policy policy);

/**
 * Prints a SCION address pair to stdout.
 * @param[in] addr The address.
 * @param[in] ia The IA.
 */
void scion_print_addr(const struct sockaddr *addr, scion_ia ia);

/**
 * Gets the type of a SCMP message.
 * @param[in] buf The serialized SCMP message.
 * @param[in] buf_len The length of the SCMP message.
 * @return The type of the SCMP message.
 *
 * @see https://docs.scion.org/en/latest/protocols/scmp.html#types
 */
uint8_t scion_scmp_get_type(const uint8_t *buf, uint16_t buf_len);

/**
 * Gets the code of a SCMP message.
 * @param[in] buf The serialized SCMP messsage.
 * @param[in] buf_len The length of the SCMP message.
 * @return The code of the SCMP message.
 */
uint8_t scion_scmp_get_code(const uint8_t *buf, uint16_t buf_len);

/**
 * Determines whether the SCMP message is an error message.
 * @param[in] buf The serialized SCMP message.
 * @param[in] buf_len The length of the serialized SCMP message.
 * @return true if the SCMP message is an error message, false otherwise.
 *
 * @see https://docs.scion.org/en/latest/protocols/scmp.html#types
 */
bool scion_scmp_is_error(const uint8_t *buf, uint16_t buf_len);

/**
 * The SCMP echo message types.
 */
enum scion_scmp_echo_type {
	/**
	 * An echo request.
	 *
	 * @see https://docs.scion.org/en/latest/protocols/scmp.html#echo-request
	 */
	SCION_ECHO_TYPE_REQUEST = 128,
	/**
	 * An echo reply.
	 *
	 * @see https://docs.scion.org/en/latest/protocols/scmp.html#echo-reply
	 */
	SCION_ECHO_TYPE_REPLY = 129
};

/**
 * An SCMP echo message.
 */
struct scion_scmp_echo {
	/** the type */
	enum scion_scmp_echo_type type;
	/** the identifier */
	uint16_t id;
	/** the sequence number */
	uint16_t seqno;
	/** the data */
	uint8_t *data;
	/** the length of the data */
	uint16_t data_length;
};

/**
 * Determines how large the serialized SCMP echo message will be.
 * @param[in] scmp_echo The SCMP echo message.
 * @return the size of the serialized SCMP echo message in bytes.
 */
uint16_t scion_scmp_echo_len(struct scion_scmp_echo *scmp_echo);

/**
 * Serializes an SCMP echo message.
 * @param[in] scmp_echo The SCMP echo message to serialize.
 * @param[out] buf The serialized SCMP echo message.
 * @param[in] buf_len The length of the serialized message.
 * @return 0 on success, a negative error code on failure.
 *
 * @note Use @link scion_scmp_echo_len @endlink to determine how large the buffer needs to be.
 */
int scion_scmp_echo_serialize(const struct scion_scmp_echo *scmp_echo, uint8_t *buf, uint16_t buf_len);

/**
 * Deserializes an SCMP echo message.
 * @param[in] buf The serialized SCMP echo message.
 * @param[in] buf_len The length of the serialized message.
 * @param[out] scmp_echo The SCMP echo message.
 * @return 0 on success, a negative error code on failure.
 */
int scion_scmp_echo_deserialize(const uint8_t *buf, uint16_t buf_len, struct scion_scmp_echo *scmp_echo);

/**
 * Frees the SCMP echo message internally.
 * @param[in] scmp_echo The SCMP echo message.
 */
void scion_scmp_echo_free_internal(struct scion_scmp_echo *scmp_echo);

#ifdef __cplusplus
}
#endif
