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
 * @file scion_timestamp.h
 *
 * The timestamp API of the csnet library.
 *
 * The kernel can timestamp the packets of a socket when they arrive and leave. A program asks for this with
 * @link scion_timestamp_set_level @endlink, or on Linux directly with the socket option SO_TIMESTAMPING, and reads
 * the timestamps of received packets from the control messages of @link scion_recvmsg @endlink. This API picks the
 * timestamps out of the control messages and falls back to the clock of the program if the kernel provided none.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <sys/socket.h>
#include <time.h>

#include <scion/scion.h>

/**
 * The clock a timestamp was taken with. A higher level is closer to the moment the packet was on the wire.
 */
enum scion_timestamp_level {
	/**
	 * Taken in user space with the system clock.
	 */
	SCION_TIMESTAMP_USER = 0,
	/**
	 * Taken by the kernel with the system clock when the packet enters or leaves the network stack. Only available on
	 * Linux.
	 */
	SCION_TIMESTAMP_KERNEL = 1,
	/**
	 * Taken by the network card with its own clock, the PTP hardware clock.
	 *
	 * @note This clock is not related to the system time. Only the difference of two hardware timestamps of the
	 * same network card is meaningful.
	 */
	SCION_TIMESTAMP_HARDWARE = 2
};

/**
 * @struct scion_timestamp
 *
 * @brief A timestamp together with the clock it was taken with.
 */
struct scion_timestamp {
	/**
	 * The clock the timestamp was taken with.
	 */
	enum scion_timestamp_level level;
	/**
	 * The time.
	 */
	struct timespec time;
};

/**
 * Sets the level of timestamps the kernel provides for the packets of a socket.
 * @param[in,out] scion_sock The socket.
 * @param[in] level The best level of timestamp to ask for. SCION_TIMESTAMP_USER asks for none, the timestamps are then
 * taken in user space.
 * @return 0 on success, SCION_ERR_NOT_SUPPORTED if the platform cannot provide the level, another negative error code
 * on failure.
 *
 * @note This sets the socket option SO_TIMESTAMPING with the flags for received and sent packets, which replaces its
 * previous value. The level of the socket is derived from the flags, also if the option is set directly. The
 * timestamps that are returned are not above it.
 * @note SCION_TIMESTAMP_HARDWARE needs a network card that supports hardware timestamps, and hardware timestamping
 * enabled for its interface with @link scion_set_hwtimestamping @endlink. Without it, the timestamps are taken by the
 * kernel.
 */
int scion_timestamp_set_level(struct scion_socket *scion_sock, enum scion_timestamp_level level);

/**
 * Gets the timestamp of a received packet.
 * @param[in,out] scion_sock The socket the packet was received on.
 * @param[in] msg The message received with @link scion_recvmsg @endlink. Its control buffer must be large enough for
 * the timestamps, for example CMSG_SPACE(3 * sizeof(struct timespec)) bytes.
 * @param[out] timestamp The best timestamp the kernel provided that is not above the level of the socket. If there is
 * none, the current time with the level SCION_TIMESTAMP_USER.
 * @return 0 on success, a negative error code on failure.
 *
 * @note The kernel provides timestamps if the level of the socket was set with @link scion_timestamp_set_level
 * @endlink.
 * @note The kernel enables the timestamps of received packets in the background when the first socket asks for them. A
 * packet that arrives right after the level was set may not have a kernel timestamp.
 */
int scion_timestamp_get_rx(
	struct scion_socket *scion_sock, const struct msghdr *msg, struct scion_timestamp *timestamp);

/**
 * Gets the timestamp of the packet that was sent last on a socket.
 * @param[in,out] scion_sock The socket.
 * @param[out] timestamp The best timestamp the kernel provided that is not above the level of the socket. If there is
 * none, the time just before the packet was sent with the level SCION_TIMESTAMP_USER.
 * @param[in] timeout_ms The time to wait for the kernel timestamp in milliseconds. It is only available after the
 * packet left the network stack.
 * @return 0 on success, SCION_ERR_NO_TIMESTAMP if no packet was sent on the socket, SCION_ERR_SOCK_OPT_INVALID if the
 * socket option SO_TIMESTAMPING asks for timestamps of sent packets without SOF_TIMESTAMPING_OPT_ID, another negative
 * error code on failure.
 *
 * @note The kernel provides timestamps of sent packets if the level of the socket was set with
 * @link scion_timestamp_set_level @endlink. If the socket option SO_TIMESTAMPING is set directly, it needs
 * SOF_TIMESTAMPING_OPT_ID to number the packets.
 * @note The kernel keeps the timestamp of each sent packet until it is read. If too many are unread, new ones are lost.
 */
int scion_timestamp_get_tx(struct scion_socket *scion_sock, struct scion_timestamp *timestamp, int timeout_ms);

/**
 * Enables or disables hardware timestamping for a network interface.
 * @param[in] ifname The name of the interface, for example "eth0".
 * @param[in] enable Whether to enable hardware timestamps of all sent and received packets.
 * @return 0 on success, a negative error code on failure.
 *
 * @note Hardware timestamps of a socket need two things: the socket option SO_TIMESTAMPING with the flags for
 * hardware timestamps, and hardware timestamping enabled for the interface, which this function does.
 * @note This changes the configuration of the interface for all programs. It needs the privilege to administer the
 * network, SCION_ERR_PERMISSION_DENIED is returned without it. A system that runs a PTP daemon usually did this
 * already.
 * @note Fails with SCION_ERR_NOT_SUPPORTED if the platform or the network card has no hardware timestamping, and with
 * SCION_ERR_ADDR_NOT_AVAILABLE if there is no such interface.
 */
int scion_set_hwtimestamping(const char *ifname, bool enable);

#ifdef __cplusplus
}
#endif
