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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef __linux__
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#endif

#include "data_plane/socket.h"
#include "data_plane/timestamp.h"
#include "scion/scion_timestamp.h"

// What the socket knows about the timestamps of the kernel.
struct scion_socket_timestamps {
	// The value of the socket option SO_TIMESTAMPING, which says how the kernel timestamps the packets.
	int flags;
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
#endif

static int user_timestamp(struct scion_timestamp *timestamp)
{
	if (clock_gettime(CLOCK_REALTIME, &timestamp->time) != 0) {
		return SCION_ERR_GENERIC;
	}

	timestamp->level = SCION_TIMESTAMP_USER;
	return 0;
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

	scion_sock->timestamps->flags = flags;
}
