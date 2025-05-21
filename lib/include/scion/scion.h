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
	SCION_GENERIC_ERR = -1,
	/**
	 * Memory allocation failed.
	 */
	SCION_MEM_ALLOC_FAIL = -2,
	/**
	 * No paths to the destination were found.
	 */
	SCION_NO_PATHS = -3,
	/**
	 * The buffer provided was not large enough.
	 */
	SCION_BUFFER_SIZE_ERR = -4,
	/**
	 * Encountered an unsupported address family.
	 *
	 * @see @link scion_addr_family @endlink
	 */
	SCION_ADDR_FAMILY_UNKNOWN = -5,
	/**
	 * Could not send the packet because the maximum SCION header length was exceeded.
	 */
	SCION_MAX_HDR_LEN_EXCEEDED = -6,
	/**
	 * The file provided was not found.
	 */
	SCION_FILE_NOT_FOUND = -7,
	/**
	 * The topology is invalid.
	 */
	SCION_TOPOLOGY_INVALID = -8,
	/**
	 * The provided address has an incompatible address family.
	 * This can happen when binding an address that has a different address family than the socket, or when
	 * sending/connecting to a host in the same AS that has a different address family than the socket.
	 */
	SCION_ADDR_FAMILY_MISMATCH = -9,
	/**
	 * The provided network has a different address family than the socket.
	 */
	SCION_NETWORK_ADDR_FAMILY_MISMATCH = -10,
	/**
	 * The protocol is not supported.
	 *
	 * @see @link scion_proto @endlink
	 */
	SCION_PROTO_UNKNOWN = -11,
	/**
	 * The socket is not connected yet.
	 */
	SCION_NOT_CONNECTED = -12,
	/**
	 * The path destination IA does not match the destination IA.
	 */
	SCION_DST_MISMATCH = -13,
	/**
	 * The provided IA string is invalid.
	 */
	SCION_INVALID_ISD_AS_STR = -14,
	/**
	 * The receive operation is in non-blocking mode and there is nothing to receive.
	 */
	SCION_WOULD_BLOCK = -15,
	/**
	 * The provided address is invalid.
	 */
	SCION_ADDR_INVALID = -16,
	/**
	 * The socket is already bound.
	 */
	SCION_ALREADY_BOUND = -17,
	/**
	 * The flag is not implemented by the library.
	 */
	SCION_FLAG_NOT_IMPLEMENTED = -18,
	/**
	 * The flag is not supported by the OS.
	 */
	SCION_FLAG_NOT_SUPPORTED = -19,
	/**
	 * Encountered an unexpected error when sending packets.
	 */
	SCION_SEND_ERR = -20,
	/**
	 * Encountered an unexpected error when receiving packets.
	 */
	SCION_RECV_ERR = -21,
	/**
	 * The address is already in use.
	 *
	 * @see [EADDRINUSE](https://man7.org/linux/man-pages/man7/ip.7.html#ERRORS)
	 */
	SCION_ADDR_IN_USE = -22,
	/**
	 * The address is not available.
	 *
	 * @see [EADDRNOTAVAIL](https://man7.org/linux/man-pages/man7/ip.7.html#ERRORS)
	 */
	SCION_ADDR_NOT_AVAILABLE = -23,
	/**
	 * The socket output queue is already full.
	 *
	 * @see [ENOBUFS](https://man7.org/linux/man-pages/man7/ip.7.html#ERRORS)
	 */
	SCION_OUTPUT_QUEUE_FULL = -24,
	/**
	 * The provided socket option is invalid.
	 */
	SCION_SOCK_OPT_INVALID = -25,
	/**
	 * The provided address buffer is too small.
	 */
	SCION_ADDR_BUF_ERR = -26,
	/**
	 * The path has expired and needs to be refreshed.
	 */
	SCION_PATH_EXPIRED = -27,
	/**
	 * The socket is not bound.
	 */
	SCION_NOT_BOUND = -28,
	/**
	 * Operation cannot be performed with a networkless socket.
	 */
	SCION_NETWORK_UNKNOWN = -29,
	/**
	 * The message is too large.
	 */
	SCION_MSG_TOO_LARGE = -30,
	/**
	 * The source address of the socket could not automatically be determined. It has to be provided by
	 * explicitly binding the socket to a non-wildcard address.
	 *
	 * @see [Source Address Determination](docs/design/source_address_determination.md)
	 */
	SCION_SRC_ADDR_UNKNOWN = -31,
	// Internal errors
	SCION_NOT_ENOUGH_DATA = -201,
	SCION_PACKET_FIELD_INVALID = -202,
	SCION_GRPC_ERR = -203,
	SCION_META_HDR_INVALID = -204,
	SCION_PATH_TYPE_INVALID = -205,
	SCION_SCMP_CODE_INVALID = -206,
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
	SCION_AF_IPV4 = AF_INET,
	/**
	 * IPv6 addresses.
	 */
	SCION_AF_IPV6 = AF_INET6
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

// TODO: docs
#define SCION_PATH_METADATA_LATENCY_IS_UNSET(latency) (latency.tv_sec == 0 && latency.tv_usec == -1)
#define SCION_PATH_METADATA_BANDWIDTH_IS_UNSET(bandwidth) (bandwidth == 0)
#define SCION_PATH_METADATA_GEO_IS_UNSET(geo) (geo.latitude == NAN && geo.longitude == NAN && geo.address == NULL)
#define SCION_PATH_METADATA_INTERNAL_HOPS_IS_UNSET(internal_hops) (internal_hops == 0)

// TODO: docs
typedef uint64_t scion_interface_id;

// TODO: docs
struct scion_path_interface {
	scion_interface_id id;
	scion_ia ia;
};

// TODO: docs
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

// TODO: docs
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

// TODO: docs
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

// TODO: docs
const struct scion_path_metadata *scion_path_get_metadata(const struct scion_path *path);

/**
 * Prints a path to stdout.
 * @param[in] path The path to print.
 */
void scion_path_print(const struct scion_path *path);

// TODO document me
void scion_path_print_metadata(const struct scion_path *path);

/**
 * @struct scion_path_collection
 *
 * @brief A collection of SCION paths.
 */
struct scion_path_collection;

/**
 * A function that matches SCION paths with custom criteria.
 * @param path The candidate path.
 * @return Whether the path matches the custom criteria.
 *
 * @note See @link scion_path_collection_find @endlink.
 */
// TODO adjust docs
typedef bool (*scion_path_predicate_fn)(struct scion_path *path, void *ctx);

struct scion_path_predicate {
	scion_path_predicate_fn fn;
	void *ctx;
};

// TODO: docs
typedef int (*scion_path_comparator_fn)(struct scion_path *path_one, struct scion_path *path_two, void *ctx);

struct scion_path_comparator {
	scion_path_comparator_fn fn;
	void *ctx;
	bool ascending;
};

/**
 * Frees a collection of paths, including the paths themselves.
 * @param[in] paths The path collection.
 */
void scion_path_collection_free(struct scion_path_collection *paths);

/**
 * Finds the first path that matches a custom criteria.
 * @param[in] paths The path collection.
 * @param predicate The predicate function that implements the custom criteria.
 * @return The first path that matches, or NULL if no path matched.
 */
// TODO update docs
struct scion_path *scion_path_collection_find(
	struct scion_path_collection *paths, struct scion_path_predicate predicate);

/**
 * Pop the first element of a path collection.
 * @param[in] paths The path collection.
 * @return The first element of the path collection, or NULL if the path collection is empty.
 */
struct scion_path *scion_path_collection_pop(struct scion_path_collection *paths);

// TODO: docs
struct scion_path *scion_path_collection_first(struct scion_path_collection *paths);

// TODO: docs
void scion_path_collection_sort(struct scion_path_collection *paths, struct scion_path_comparator comparator);

// TODO: docs
void scion_path_collection_filter(struct scion_path_collection *paths, struct scion_path_predicate predicate);

// TODO: docs
size_t scion_path_collection_size(struct scion_path_collection *paths);

// TODO: docs
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
 * A SCION path policy.
 */
struct scion_policy {
	/**
	 * TODO: add some details here
	 */
	void (*filter)(struct scion_path_collection *paths);
};

/**
 * A policy that prefers paths with higher MTUs.
 */
extern const struct scion_policy scion_policy_highest_mtu;

/**
 * A policy that prefers paths with few hops.
 */
extern const struct scion_policy scion_policy_least_hops;

// TODO document me
extern const struct scion_policy scion_policy_lowest_latency;

// TODO document me
extern const struct scion_policy scion_policy_highest_bandwidth;

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
 * @see scion_set_scmp_error_cb
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
 * @param[in] ctx The context that is passed to every invocation of the callback. Must be NULL, if not context is
 * needed.
 * @return 0 on success, a negative error code on failure.
 */
int scion_setsockerrcb(struct scion_socket *scion_sock, scion_socket_scmp_error_cb cb, void *ctx);

// TODO: docs
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
