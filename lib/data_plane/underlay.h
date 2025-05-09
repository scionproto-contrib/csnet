// Copyright 2025 ETH Zurich
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

#include <sys/socket.h>

#include "scion/scion.h"

struct scion_underlay {
	enum scion_addr_family addr_family;
	struct sockaddr_storage addr;
	socklen_t addrlen;
};

/**
 * Determines which source address can be used to communicate with the underlay by connecting to it.
 */
int scion_underlay_probe(struct scion_underlay *underlay, struct sockaddr *addr, socklen_t *addrlen);
