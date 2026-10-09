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

#include <arpa/inet.h>
#include <assert.h>
#include <string.h>

#include "util/addr.h"

int scion_addr_parse(const char *str, uint16_t port, scion_ia *ia, struct sockaddr *addr, socklen_t *addrlen)
{
	assert(str);
	assert(ia);
	assert(addr);
	assert(addrlen);

	size_t str_len = strlen(str);
	const char *separator = memchr(str, ',', str_len);
	if (separator == NULL) {
		return SCION_ERR_ADDR_INVALID;
	}

	size_t ia_len = (size_t)(separator - str);
	if (scion_ia_parse(str, ia_len, ia) != 0) {
		return SCION_ERR_ADDR_INVALID;
	}

	size_t ip_len = str_len - ia_len - 1;
	if (ip_len == 0) {
		return SCION_ERR_ADDR_INVALID;
	}

	char ip_str[ip_len + 1];
	(void)strcpy(ip_str, str + ia_len + 1);

	if (*addrlen >= sizeof(struct sockaddr_in)
		&& inet_pton(AF_INET, ip_str, &((struct sockaddr_in *)addr)->sin_addr) == 1) {
		((struct sockaddr_in *)addr)->sin_family = AF_INET;
		((struct sockaddr_in *)addr)->sin_port = htons(port);
		*addrlen = sizeof(struct sockaddr_in);
	} else if (*addrlen >= sizeof(struct sockaddr_in6)
			   && inet_pton(AF_INET6, ip_str, &((struct sockaddr_in6 *)addr)->sin6_addr) == 1) {
		((struct sockaddr_in6 *)addr)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)addr)->sin6_port = htons(port);
		*addrlen = sizeof(struct sockaddr_in6);
	} else {
		return SCION_ERR_ADDR_INVALID;
	}

	return 0;
}

int scion_addr_from_ip(enum scion_addr_family family, const char *ip, uint16_t port, struct sockaddr_storage *addr,
	socklen_t *addrlen)
{
	assert(addr);
	assert(addrlen);

	(void)memset(addr, 0, sizeof(*addr));

	if (family == SCION_AF_INET) {
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		addr_in->sin_family = AF_INET;
		addr_in->sin_port = htons(port);

		if (ip == NULL) {
			addr_in->sin_addr.s_addr = htonl(INADDR_ANY);
		} else if (inet_pton(AF_INET, ip, &addr_in->sin_addr) != 1) {
			return SCION_ERR_ADDR_INVALID;
		}

		*addrlen = sizeof(*addr_in);
	} else if (family == SCION_AF_INET6) {
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
		addr_in6->sin6_family = AF_INET6;
		addr_in6->sin6_port = htons(port);

		if (ip == NULL) {
			addr_in6->sin6_addr = in6addr_any;
		} else if (inet_pton(AF_INET6, ip, &addr_in6->sin6_addr) != 1) {
			return SCION_ERR_ADDR_INVALID;
		}

		*addrlen = sizeof(*addr_in6);
	} else {
		return SCION_ERR_ADDR_FAMILY_UNKNOWN;
	}

	return 0;
}
