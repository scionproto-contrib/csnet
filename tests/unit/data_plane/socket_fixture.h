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

#include <netinet/in.h>
#include <stdint.h>

#include "scion/scion.h"

struct scion_list;

struct socket_fixture {
	struct scion_topology *topology;
	struct scion_network *network;
	struct scion_list *sockets;
};

void free_test_border_router(void *value);
int setup_fixture(void **state);
int teardown_fixture(void **state);
struct scion_socket *open_socket(struct socket_fixture *fixture, int type, enum scion_proto protocol);
struct sockaddr_in loopback_addr(uint16_t port);
void bind_loopback(struct scion_socket *sock);
struct sockaddr_in bound_address(struct scion_socket *sock);
void set_receive_timeout(struct scion_socket *sock, long milliseconds);
scion_ia local_ia_of(struct socket_fixture *fixture);
