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

#pragma once

#include <time.h>

#include "data_plane/socket.h"

/**
 * Creates the state of the timestamps of a socket. Returns NULL if there is no memory.
 */
struct scion_socket_timestamps *scion_timestamp_state_create(void);

/**
 * Frees the state of the timestamps of a socket.
 */
void scion_timestamp_state_free(struct scion_socket_timestamps *state);

/**
 * Updates what the library knows about the timestamping of a socket after the socket option SO_TIMESTAMPING was set.
 */
void scion_timestamp_flags_changed(struct scion_socket *scion_sock, int flags);

/**
 * Records the time before a packet was sent on the socket and, if the kernel gives the packets ids, its id.
 */
void scion_timestamp_record_sent(struct scion_socket *scion_sock, const struct timespec *time);

