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
#include <cmocka.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "common/isd_as.h"
#include "control_plane/network.h"
#include "control_plane/topology.h"
#include "scion/scion.h"
#include "socket_fixture.h"
#include "util/list.h"

// The tests only use loopback sockets in the local AS. A path within the local AS is empty, so it is created without a
// control service and packets go straight to the destination address.

void free_test_border_router(void *value)
{
	struct scion_border_router *br = value;
	free(br->ifids);
	free(br);
}

static void close_socket(void *value)
{
	scion_close(value);
}

int setup_fixture(void **state)
{
	struct socket_fixture *fixture = calloc(1, sizeof(*fixture));
	*state = fixture;

	fixture->topology = calloc(1, sizeof(*fixture->topology));
	assert_int_equal(scion_ia_parse("1-ff00:0:110", strlen("1-ff00:0:110"), &fixture->topology->ia), 0);
	fixture->topology->local_addr_family = SCION_AF_INET;
	fixture->topology->border_routers = scion_list_create(SCION_LIST_CUSTOM_FREE(free_test_border_router));

	// The socket determines its source address by connecting to a border router.
	struct scion_border_router *br = calloc(1, sizeof(*br));
	br->ifids = malloc(sizeof(*br->ifids));
	br->ifids[0] = 1;
	br->ifid_len = 1;
	struct sockaddr_in *br_addr = (struct sockaddr_in *)&br->addr;
	br_addr->sin_family = AF_INET;
	br_addr->sin_port = htons(30042);
	br_addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	br->addr_len = sizeof(*br_addr);
	scion_list_append(fixture->topology->border_routers, br);

	assert_int_equal(scion_network(&fixture->network, fixture->topology), 0);
	fixture->sockets = scion_list_create(SCION_LIST_CUSTOM_FREE(close_socket));
	return 0;
}

int teardown_fixture(void **state)
{
	struct socket_fixture *fixture = *state;
	scion_list_free(fixture->sockets);
	scion_network_free(fixture->network);
	scion_topology_free(fixture->topology);
	free(fixture);
	return 0;
}

struct scion_socket *open_socket(struct socket_fixture *fixture, int type, enum scion_proto protocol)
{
	struct scion_socket *sock;
	assert_int_equal(scion_socket(&sock, SCION_AF_INET, type, protocol, fixture->network), 0);
	scion_list_append(fixture->sockets, sock);
	return sock;
}

struct sockaddr_in loopback_addr(uint16_t port)
{
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return addr;
}

// Binds the socket to an ephemeral loopback port.
void bind_loopback(struct scion_socket *sock)
{
	struct sockaddr_in addr = loopback_addr(0);
	assert_int_equal(scion_bind(sock, (struct sockaddr *)&addr, sizeof(addr)), 0);
}

// Returns the address a bound socket is bound to.
struct sockaddr_in bound_address(struct scion_socket *sock)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	assert_int_equal(scion_getsockname(sock, (struct sockaddr *)&addr, &len, NULL), 0);
	return addr;
}

void set_receive_timeout(struct scion_socket *sock, long milliseconds)
{
	struct timeval timeout = { .tv_sec = milliseconds / 1000, .tv_usec = (milliseconds % 1000) * 1000 };
	assert_int_equal(scion_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), 0);
}

scion_ia local_ia_of(struct socket_fixture *fixture)
{
	return scion_topology_get_local_ia(fixture->topology);
}

// The kernel enables the software receive timestamps in the background when the first socket asks for them. A packet
// that arrives right after the socket option is set may not get a timestamp, so wait a bit.
void wait_for_kernel_timestamping(void)
{
	(void)usleep(50 * 1000);
}
