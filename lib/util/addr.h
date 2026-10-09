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

#include <stdint.h>
#include <sys/socket.h>

#include "scion/scion.h"

/**
 * Parses a SCION address of the form "<ISD-AS>,<IP>", for example "2-ff00:0:222,fd00:f00d:cafe::7f00:55".
 * @param[in] str The string to parse.
 * @param[in] port The port of the resulting address.
 * @param[out] ia The ISD-AS.
 * @param[out] addr The IP address.
 * @param[in,out] addrlen The size of addr on input, the size of the address on output.
 * @return 0 on success, SCION_ERR_ADDR_INVALID if the string is invalid.
 */
int scion_addr_parse(const char *str, uint16_t port, scion_ia *ia, struct sockaddr *addr, socklen_t *addrlen);

/**
 * Creates an IP address from a string.
 * @param[in] family The address family.
 * @param[in] ip The IP address as a string, NULL for the wildcard address.
 * @param[in] port The port of the resulting address.
 * @param[out] addr The IP address.
 * @param[out] addrlen The size of the address.
 * @return 0 on success, SCION_ERR_ADDR_INVALID if the IP address is invalid for the family.
 */
int scion_addr_from_ip(enum scion_addr_family family, const char *ip, uint16_t port, struct sockaddr_storage *addr,
	socklen_t *addrlen);
