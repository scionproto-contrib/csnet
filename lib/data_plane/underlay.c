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

#include <assert.h>
#include <errno.h>
#include <unistd.h>

#include "data_plane/underlay.h"

int scion_underlay_probe(struct scion_underlay *underlay, struct sockaddr *addr, socklen_t *addrlen)
{
	assert(underlay);
	int ret;

	int sock_fd = socket((int)underlay->addr_family, SOCK_DGRAM, 0);
	if (sock_fd == -1) {
		return SCION_ERR_GENERIC;
	}

	do {
		ret = connect(sock_fd, (struct sockaddr *)&underlay->addr, underlay->addrlen);
	} while (ret == -1 && errno == EINTR);

	if (ret != 0) {
		ret = SCION_ERR_GENERIC;
		goto cleanup_socket;
	}

	ret = getsockname(sock_fd, addr, addrlen);
	if (ret != 0) {
		ret = SCION_ERR_GENERIC;
	}

cleanup_socket:
	close(sock_fd);

	return ret;
}
