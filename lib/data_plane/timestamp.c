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

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __linux__
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <unistd.h>
#endif

#include "data_plane/socket.h"
#include "data_plane/timestamp.h"
#include "scion/scion_timestamp.h"

// What the socket knows about the timestamps of the kernel.
struct scion_socket_timestamps {
	// The value of the socket option SO_TIMESTAMPING, which says how the kernel timestamps the packets.
	int flags;
	// The id the kernel gives to the next sent packet.
	uint32_t next_id;
	// The packet that was sent last.
	struct {
		bool is_set;
		// The time taken in user space just before the packet was sent.
		struct timespec user_time;
		// The id the kernel gave to the packet to match it to its timestamp, only if the kernel gives ids to packets.
		bool has_id;
		uint32_t id;
		// The timestamps of the kernel, once they were read from the error queue.
		bool is_read;
		struct timespec kernel_time;
		struct timespec hardware_time;
	} last_sent;
};

struct scion_socket_timestamps *scion_timestamp_state_create(void)
{
	return calloc(1, sizeof(struct scion_socket_timestamps));
}

void scion_timestamp_state_free(struct scion_socket_timestamps *state)
{
	free(state);
}

#ifdef __linux__
// A buffer for the control messages of a message from the error queue. They are the timestamps of the kernel, and the
// error with the id of the packet and the address of the node that sent it. The union gives the buffer the
// alignment of a control message header, which a plain char array does not guarantee.
union error_queue_control {
	char buf[CMSG_SPACE(sizeof(struct scm_timestamping))
			 + CMSG_SPACE(sizeof(struct sock_extended_err) + sizeof(struct sockaddr_in6))];
	struct cmsghdr align;
};

// Finds the timestamps of a packet in the control messages of its message.
static bool find_kernel_timestamps(const struct msghdr *msg, struct scm_timestamping *timestamps)
{
	// The macros need a pointer to a non-const message, but do not change it.
	struct msghdr msg_copy = *msg;

	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg_copy); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg_copy, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING
			&& cmsg->cmsg_len >= CMSG_LEN(sizeof(*timestamps))) {
			(void)memcpy(timestamps, CMSG_DATA(cmsg), sizeof(*timestamps));
			return true;
		}
	}

	return false;
}

static bool is_set(const struct timespec *time)
{
	return time->tv_sec != 0 || time->tv_nsec != 0;
}

// The level of the timestamps the kernel is asked for with the flags of the socket option SO_TIMESTAMPING.
static enum scion_timestamp_level level_of(int flags)
{
	if ((flags & (SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_TX_HARDWARE)) != 0) {
		return SCION_TIMESTAMP_HARDWARE;
	}

	if ((flags & (SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_TX_SOFTWARE)) != 0) {
		return SCION_TIMESTAMP_KERNEL;
	}

	return SCION_TIMESTAMP_USER;
}

// Selects the best timestamp the kernel provided that is not above max_level.
static bool select_timestamp(const struct timespec *kernel_time, const struct timespec *hardware_time,
	enum scion_timestamp_level max_level, struct scion_timestamp *timestamp)
{
	if (max_level >= SCION_TIMESTAMP_HARDWARE && is_set(hardware_time)) {
		timestamp->level = SCION_TIMESTAMP_HARDWARE;
		timestamp->time = *hardware_time;
		return true;
	}

	if (max_level >= SCION_TIMESTAMP_KERNEL && is_set(kernel_time)) {
		timestamp->level = SCION_TIMESTAMP_KERNEL;
		timestamp->time = *kernel_time;
		return true;
	}

	return false;
}

// Finds the id of the packet in the control messages of a message from the error queue, if the message is the
// timestamp of a sent packet.
static bool find_transmit_id(const struct msghdr *msg, uint32_t *id)
{
	struct msghdr msg_copy = *msg;

	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg_copy); cmsg != NULL; cmsg = CMSG_NXTHDR(&msg_copy, cmsg)) {
		bool is_error = (cmsg->cmsg_level == SOL_IP && cmsg->cmsg_type == IP_RECVERR)
						|| (cmsg->cmsg_level == SOL_IPV6 && cmsg->cmsg_type == IPV6_RECVERR);
		if (!is_error || cmsg->cmsg_len < CMSG_LEN(sizeof(struct sock_extended_err))) {
			continue;
		}

		struct sock_extended_err err;
		(void)memcpy(&err, CMSG_DATA(cmsg), sizeof(err));
		if (err.ee_origin == SO_EE_ORIGIN_TIMESTAMPING && err.ee_info == SCM_TSTAMP_SND) {
			*id = err.ee_data;
			return true;
		}
	}

	return false;
}

// The kernel timestamps the sent packets and gives them ids if both are asked for.
static bool has_packet_ids(int flags)
{
	return (flags & (SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE)) != 0
		   && (flags & SOF_TIMESTAMPING_OPT_ID) != 0;
}

// Reads the messages of the error queue of the socket, until there is none left or the one of the last sent packet
// was read. The kernel reports the timestamp of every packet there, also those that nobody asks for.
static int read_transmit_timestamp(struct scion_socket *scion_sock, int timeout_ms)
{
	struct scion_socket_timestamps *state = scion_sock->timestamps;
	ssize_t ret;

	struct timespec start;
	(void)clock_gettime(CLOCK_MONOTONIC, &start);

	while (true) {
		struct timespec now;
		(void)clock_gettime(CLOCK_MONOTONIC, &now);
		long elapsed_ms = (long)(now.tv_sec - start.tv_sec) * 1000 + (now.tv_nsec - start.tv_nsec) / 1000000;
		long remaining_ms = timeout_ms > elapsed_ms ? timeout_ms - elapsed_ms : 0;

		// The error queue is not selected for reading, only for errors.
		struct pollfd pfd = { .fd = scion_sock->socket_fd, .events = 0, .revents = 0 };
		ret = poll(&pfd, 1, (int)remaining_ms);
		if (ret < 0) {
			if (errno == EINTR) {
				continue;
			}
			return SCION_ERR_GENERIC;
		}
		if (ret == 0) {
			// No timestamp in time
			return 0;
		}
		if ((pfd.revents & (POLLNVAL | POLLHUP)) != 0) {
			return SCION_ERR_RECV_FAIL;
		}

		union error_queue_control control;
		struct msghdr msg = { .msg_control = control.buf, .msg_controllen = sizeof(control.buf) };
		ret = scion_recvmsg(scion_sock, &msg, MSG_ERRQUEUE | MSG_DONTWAIT, NULL, NULL);
		if (ret == SCION_ERR_WOULD_BLOCK) {
			// The error is not in the queue, but an error of the socket. Clear it, or poll returns right away again.
			int socket_error;
			socklen_t socket_error_len = sizeof(socket_error);
			(void)getsockopt(scion_sock->socket_fd, SOL_SOCKET, SO_ERROR, &socket_error, &socket_error_len);
			continue;
		}
		if (ret < 0) {
			return (int)ret;
		}

		uint32_t id;
		struct scm_timestamping timestamps;
		if (!find_transmit_id(&msg, &id) || !find_kernel_timestamps(&msg, &timestamps)) {
			continue;
		}

		// A message with another id is the timestamp of another packet.
		if (id == state->last_sent.id) {
			state->last_sent.is_read = true;
			state->last_sent.kernel_time = timestamps.ts[0];
			state->last_sent.hardware_time = timestamps.ts[2];
			return 0;
		}
	}
}

// Removes the timestamps of sent packets that nobody read from the error queue.
static void drain_error_queue(struct scion_socket *scion_sock)
{
	union error_queue_control control;

	while (true) {
		struct msghdr msg = { .msg_control = control.buf, .msg_controllen = sizeof(control.buf) };
		if (scion_recvmsg(scion_sock, &msg, MSG_ERRQUEUE | MSG_DONTWAIT, NULL, NULL) < 0) {
			return;
		}
	}
}
#endif

static int user_timestamp(struct scion_timestamp *timestamp)
{
	if (clock_gettime(CLOCK_REALTIME, &timestamp->time) != 0) {
		return SCION_ERR_GENERIC;
	}

	timestamp->level = SCION_TIMESTAMP_USER;
	return 0;
}

int scion_timestamp_set_level(struct scion_socket *scion_sock, enum scion_timestamp_level level)
{
	assert(scion_sock);

#ifdef __linux__
	// The numbering of the sent packets lets scion_timestamp_get_tx() match a timestamp to its packet.
	int flags = 0;
	if (level >= SCION_TIMESTAMP_KERNEL) {
		flags |= SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_TX_SOFTWARE
				 | SOF_TIMESTAMPING_OPT_ID;
	}
	if (level >= SCION_TIMESTAMP_HARDWARE) {
		flags |= SOF_TIMESTAMPING_RAW_HARDWARE | SOF_TIMESTAMPING_RX_HARDWARE | SOF_TIMESTAMPING_TX_HARDWARE;
	}

	return scion_setsockopt(scion_sock, SOL_SOCKET, SO_TIMESTAMPING, &flags, sizeof(flags));
#else
	return level == SCION_TIMESTAMP_USER ? 0 : SCION_ERR_NOT_SUPPORTED;
#endif
}

int scion_timestamp_get_rx(struct scion_socket *scion_sock, const struct msghdr *msg, struct scion_timestamp *timestamp)
{
	assert(scion_sock);
	assert(msg);
	assert(timestamp);

#ifdef __linux__
	// The kernel returns the timestamp of the system clock first and the one of the hardware clock last. The one
	// in between is deprecated.
	enum scion_timestamp_level level = level_of(scion_sock->timestamps->flags);
	struct scm_timestamping timestamps;
	if (level > SCION_TIMESTAMP_USER && find_kernel_timestamps(msg, &timestamps)) {
		if (select_timestamp(&timestamps.ts[0], &timestamps.ts[2], level, timestamp)) {
			return 0;
		}
	}
#else
	(void)scion_sock;
	(void)msg;
#endif

	return user_timestamp(timestamp);
}

void scion_timestamp_flags_changed(struct scion_socket *scion_sock, int flags)
{
	assert(scion_sock);

	struct scion_socket_timestamps *state = scion_sock->timestamps;

#ifdef __linux__
	// The kernel starts numbering the sent packets from zero when the numbering is switched on. Without it, the
	// timestamps of the packets that nobody read are not needed any more, and would be taken for new ones.
	bool had_ids = (state->flags & SOF_TIMESTAMPING_OPT_ID) != 0;
	bool has_ids = (flags & SOF_TIMESTAMPING_OPT_ID) != 0;
	if (had_ids != has_ids) {
		drain_error_queue(scion_sock);
		state->next_id = 0;
		state->last_sent.has_id = false;
	}
#endif

	state->flags = flags;
}

void scion_timestamp_record_sent(struct scion_socket *scion_sock, const struct timespec *time)
{
	assert(scion_sock);
	assert(time);

	struct scion_socket_timestamps *state = scion_sock->timestamps;

	state->last_sent.is_set = true;
	state->last_sent.user_time = *time;
	state->last_sent.is_read = false;

#ifdef __linux__
	state->last_sent.has_id = has_packet_ids(state->flags);
	if (state->last_sent.has_id) {
		state->last_sent.id = state->next_id++;
	}
#endif
}

int scion_timestamp_get_tx(struct scion_socket *scion_sock, struct scion_timestamp *timestamp, int timeout_ms)
{
	assert(scion_sock);
	assert(timestamp);

	struct scion_socket_timestamps *state = scion_sock->timestamps;

	if (!state->last_sent.is_set) {
		return SCION_ERR_NO_TIMESTAMP;
	}

#ifdef __linux__
	int flags = state->flags;

	// Without the numbering, the kernel timestamp cannot be matched to the packet.
	if ((flags & (SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_TX_HARDWARE)) != 0
		&& (flags & SOF_TIMESTAMPING_OPT_ID) == 0) {
		return SCION_ERR_SOCK_OPT_INVALID;
	}

	enum scion_timestamp_level level = level_of(flags);
	if (level > SCION_TIMESTAMP_USER && state->last_sent.has_id) {
		if (!state->last_sent.is_read) {
			int ret = read_transmit_timestamp(scion_sock, timeout_ms);
			if (ret != 0) {
				return ret;
			}
		}

		if (state->last_sent.is_read) {
			if (select_timestamp(&state->last_sent.kernel_time, &state->last_sent.hardware_time, level,
					timestamp)) {
				return 0;
			}
		}
	}
#else
	(void)timeout_ms;
#endif

	// The kernel provided no timestamp
	timestamp->level = SCION_TIMESTAMP_USER;
	timestamp->time = state->last_sent.user_time;

	return 0;
}

int scion_set_hwtimestamping(const char *ifname, bool enable)
{
	assert(ifname);

#ifdef __linux__
	if (ifname[0] == '\0' || strlen(ifname) >= IFNAMSIZ) {
		return SCION_ERR_ADDR_NOT_AVAILABLE;
	}

	// The driver may change the filter to the closest one it supports.
	struct hwtstamp_config config = { 0 };
	config.tx_type = enable ? HWTSTAMP_TX_ON : HWTSTAMP_TX_OFF;
	config.rx_filter = enable ? HWTSTAMP_FILTER_ALL : HWTSTAMP_FILTER_NONE;

	struct ifreq request = { 0 };
	(void)strncpy(request.ifr_name, ifname, IFNAMSIZ - 1);
	request.ifr_data = (char *)&config;

	// Any socket can be used to reach the interface.
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		(void)fprintf(stderr, "ERROR: encountered an unexpected error when creating a socket (%s, code %d)\n",
			strerror(errno), errno);
		return SCION_ERR_GENERIC;
	}

	int ret = ioctl(fd, SIOCSHWTSTAMP, &request);
	int error = errno;
	(void)close(fd);

	if (ret == -1) {
		if (error == ENODEV) {
			return SCION_ERR_ADDR_NOT_AVAILABLE;
		}
		if (error == EPERM || error == EACCES) {
			return SCION_ERR_PERMISSION_DENIED;
		}
		if (error == EOPNOTSUPP || error == EINVAL || error == ERANGE) {
			return SCION_ERR_NOT_SUPPORTED;
		}

		(void)fprintf(stderr,
			"ERROR: encountered an unexpected error when setting hardware timestamping (%s, code %d)\n",
			strerror(error), error);
		return SCION_ERR_GENERIC;
	}

	return 0;
#else
	(void)enable;
	return SCION_ERR_NOT_SUPPORTED;
#endif
}
