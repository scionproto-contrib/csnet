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
 * The csnet library.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

#define SCION_SO_DEBUG 200

#define SCION_FETCH_OPT_DEBUG 1

/**
 * The maximum length a string representation of an IA may require (including the null terminator).
 */
#define SCION_IA_STRLEN 21

/**
 * Possible error codes returned by the csnet library.
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
	/**
	 * The bootstrapping process failed. Make sure the network is configured correctly.
	 */
	SCION_ERR_BOOTSTRAPPING_FAIL = -32,
	/**
	 * The socket type is not supported.
	 *
	 * @see @link scion_sock_type @endlink
	 */
	SCION_ERR_SOCK_TYPE_UNKNOWN = -33,
	/**
	 * The protocol is not compatible with the socket type.
	 */
	SCION_ERR_PROTO_INCOMPATIBLE = -34,
	/**
	 * An index is out of range.
	 */
	SCION_ERR_INDEX_OUT_OF_RANGE = -35,
	/**
	 * There is no timestamp, because no packet has been sent yet.
	 */
	SCION_ERR_NO_TIMESTAMP = -36,
	/**
	 * The operation is not supported by the platform or the network interface.
	 */
	SCION_ERR_NOT_SUPPORTED = -37,
	/**
	 * The operation requires privileges the process does not have.
	 */
	SCION_ERR_PERMISSION_DENIED = -38,
	/**
	 * The control message is not implemented by the library.
	 */
	SCION_ERR_CONTROL_MSG_NOT_IMPLEMENTED = -39,
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
 * The socket types that are supported.
 *
 * May be combined with @link scion_sock_flag @endlink
 */
enum scion_sock_type {
	/**
	 * Datagram socket type.
	 *
	 */
	SCION_SOCK_DGRAM = SOCK_DGRAM,
	/**
	 * Raw socket type.
	 */
	SCION_SOCK_RAW = SOCK_RAW,
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
 * Gets the string representation of an IA.
 * @param[in] ia The IA.
 * @param[in,out] buf The buffer in which the string is stored.
 * @param[in] buflen The length of the buffer.
 * @return 0 on success, a negative error code on failure.
 *
 * @see The macro SCION_IA_STRLEN can be used to allocate a buffer of appropriate size.
 */
int scion_ia_str(scion_ia ia, char *buf, size_t buflen);

/**
 * Prints an IA to stdout.
 * @param[in] ia The IA.
 */
void scion_ia_print(scion_ia ia);

/**
 * Prints a SCION address pair to stdout.
 * @param[in] addr The address.
 * @param[in] ia The IA.
 */
void scion_addr_print(const struct sockaddr *addr, scion_ia ia);

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
 * Tries to automatically bootstrap the topology and store it.
 * @param[in] topology_path The path used to store the topology file.
 * @return 0 on success, a negative error code on failure.
 *
 * @note Currently, only the DNS bootstrapping method is supported.
 *
 * @see [End Host Bootstrapping - DNS](https://docs.scion.org/en/latest/dev/design/endhost-bootstrap.html#dns)
 */
int scion_bootstrap(const char *topology_path);

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

// A SCION path, see scion_path.h.
struct scion_path;

/**
 * An interface identifier.
 */
typedef uint64_t scion_ifid;

/**
 * @struct scion_socket
 *
 * @brief A SCION socket.
 */
struct scion_socket;

/**
 * Initializes a SCION socket.
 * @param[out] scion_sock The resulting SCION socket.
 * @param[in] addr_family The address family to use.
 * @param[in] type The @link scion_sock_type @endlink of the socket. Can be bitwise ORed with SCION_NONBLOCK to make
 * socket non-blocking.
 * @param[in] protocol The protocol to use.
 * @param[in] network The network to use. If NULL, the socket is in networkless mode. Networkless sockets cannot be
 * connected, must always be bound manually before sending and always need an explicit path when sending.
 * @return 0 on success, a negative error code on failure.
 */
int scion_socket(struct scion_socket **scion_sock, enum scion_addr_family addr_family, int type,
	enum scion_proto protocol, struct scion_network *network);

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
 * Sends a message to a destination.
 * @param[in,out] scion_sock The socket.
 * @param[in] msg The message to send.
 * @param[in] flags The send flags to use. Must be 0 if no flags should be used.
 * @param[in] dst_ia The destination IA. If it is 0, the connected destination IA is used.
 * @param[in] path The path to use. If NULL, a suitable path is automatically used.
 * @return The amount of data sent on success, a negative error code on failure.
 *
 * @note The currently supported send flags are MSG_CONFIRM, MSG_DONTWAIT and MSG_MORE.
 * @note No control messages are implemented for sending. A message with control messages is rejected with
 * SCION_ERR_CONTROL_MSG_NOT_IMPLEMENTED.
 */
ssize_t scion_sendmsg(
	struct scion_socket *scion_sock, const struct msghdr *msg, int flags, scion_ia dst_ia, struct scion_path *path);

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
 * @param[out] buf The buffer to store the received packet.
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
 * Receives a message on the SCION socket.
 * @param[in,out] scion_sock The socket.
 * @param[in,out] msg The received message.
 * @param[in] flags The receive flags to use. Must be 0 if no flags should be used.
 * @param[out] src_ia The sender IA. If NULL, the IA is not returned.
 * @param[out] path The path the packet took. If NULL, the path is not returned.
 * @return The amount of data received on success, a negative error code on failure.
 *
 * @note The currently supported receive flags are MSG_DONTWAIT and MSG_PEEK. On Linux, MSG_ERRQUEUE is supported, too.
 * @note The only control message that is returned in the control buffer of the message is SCM_TIMESTAMPING, which the
 * socket option SO_TIMESTAMPING enables. The other control messages of the underlying socket describe it and not the
 * SCION packet, so they are removed.
 * @note MSG_ERRQUEUE reads the error queue of the underlying socket, where the kernel puts the transmit timestamps.
 * The message is returned as the kernel provides it, without the sender IA and the path.
 */
ssize_t scion_recvmsg(
	struct scion_socket *scion_sock, struct msghdr *msg, int flags, scion_ia *src_ia, struct scion_path **path);

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

#ifdef __cplusplus
}
#endif
