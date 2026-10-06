// Copyright 2024 ETH Zurich
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
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "common/isd_as.h"
#include "control_plane/network.h"
#include "control_plane/topology.h"
#include "data_plane/path.h"
#include "data_plane/socket.h"
#include "scion/scion.h"
#include "test_socket.h"
#include "util/list.h"

// The tests only use loopback sockets in the local AS. A path within the local AS is empty, so it is created without a
// control service and packets go straight to the destination address.

#define MAX_SOCKETS 4

struct socket_fixture {
	struct scion_topology *topology;
	struct scion_network *network;
	struct scion_socket *sockets[MAX_SOCKETS];
	size_t socket_count;
};

static void free_test_border_router(void *value)
{
	struct scion_border_router *br = value;
	free(br->ifids);
	free(br);
}

static int setup_fixture(void **state)
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
	return 0;
}

static int teardown_fixture(void **state)
{
	struct socket_fixture *fixture = *state;
	for (size_t i = 0; i < fixture->socket_count; i++) {
		scion_close(fixture->sockets[i]);
	}
	scion_network_free(fixture->network);
	scion_topology_free(fixture->topology);
	free(fixture);
	return 0;
}

static struct scion_socket *open_socket(struct socket_fixture *fixture, int type, enum scion_proto protocol)
{
	assert_true(fixture->socket_count < MAX_SOCKETS);
	struct scion_socket **slot = &fixture->sockets[fixture->socket_count];
	assert_int_equal(scion_socket(slot, SCION_AF_INET, type, protocol, fixture->network), 0);
	fixture->socket_count++;
	return *slot;
}

static struct sockaddr_in loopback_addr(uint16_t port)
{
	struct sockaddr_in addr = { .sin_family = AF_INET, .sin_port = htons(port) };
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	return addr;
}

// Binds the socket to an ephemeral loopback port.
static void bind_loopback(struct scion_socket *sock)
{
	struct sockaddr_in addr = loopback_addr(0);
	assert_int_equal(scion_bind(sock, (struct sockaddr *)&addr, sizeof(addr)), 0);
}

// Returns the address a bound socket is bound to.
static struct sockaddr_in bound_address(struct scion_socket *sock)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	assert_int_equal(scion_getsockname(sock, (struct sockaddr *)&addr, &len, NULL), 0);
	return addr;
}

static void test_socket_creation_errors(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sock;

	assert_int_equal(scion_socket(&sock, SCION_AF_INET6, SCION_SOCK_DGRAM, SCION_PROTO_UDP, fixture->network),
		SCION_ERR_NETWORK_ADDR_FAMILY_MISMATCH);
	assert_int_equal(scion_socket(&sock, (enum scion_addr_family)12345, SCION_SOCK_DGRAM, SCION_PROTO_UDP, NULL),
		SCION_ERR_ADDR_FAMILY_UNKNOWN);
	assert_int_equal(scion_socket(&sock, SCION_AF_INET, SCION_SOCK_DGRAM, SCION_PROTO_SCMP, fixture->network),
		SCION_ERR_PROTO_INCOMPATIBLE);
	assert_int_equal(scion_socket(&sock, SCION_AF_INET, SOCK_STREAM, SCION_PROTO_UDP, fixture->network),
		SCION_ERR_SOCK_TYPE_UNKNOWN);
	assert_int_equal(scion_socket(&sock, SCION_AF_INET, SCION_SOCK_RAW, (enum scion_proto)99, fixture->network),
		SCION_ERR_PROTO_UNKNOWN);
}

static void test_socket_without_network(void **state)
{
	(void)state;
	struct scion_socket *sock;
	assert_int_equal(scion_socket(&sock, SCION_AF_INET, SCION_SOCK_DGRAM, SCION_PROTO_UDP, NULL), 0);

	struct sockaddr_in dst = loopback_addr(30000);
	assert_int_equal(scion_send(sock, "x", 1, 0), SCION_ERR_NETWORK_UNKNOWN);
	assert_int_equal(scion_connect(sock, (struct sockaddr *)&dst, sizeof(dst), 0), SCION_ERR_NETWORK_UNKNOWN);

	// Binding works, but without a network the socket has no ISD-AS.
	struct sockaddr_in addr = loopback_addr(0);
	assert_int_equal(scion_bind(sock, (struct sockaddr *)&addr, sizeof(addr)), 0);
	scion_ia ia;
	assert_int_equal(scion_getsockname(sock, NULL, NULL, &ia), SCION_ERR_NETWORK_UNKNOWN);

	assert_int_equal(scion_close(sock), 0);
}

static void test_socket_bind_and_getsockname(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sock = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	assert_int_equal(scion_getsockname(sock, (struct sockaddr *)&addr, &len, NULL), SCION_ERR_NOT_BOUND);

	bind_loopback(sock);
	struct sockaddr_in bound = bound_address(sock);
	assert_int_equal(bound.sin_family, AF_INET);
	assert_uint_equal(ntohl(bound.sin_addr.s_addr), INADDR_LOOPBACK);
	assert_true(bound.sin_port != 0);

	scion_ia ia;
	assert_int_equal(scion_getsockname(sock, NULL, NULL, &ia), 0);
	assert_true(ia == scion_topology_get_local_ia(fixture->topology));

	len = 1;
	assert_int_equal(scion_getsockname(sock, (struct sockaddr *)&addr, &len, NULL), SCION_ERR_ADDR_BUF_TOO_SMALL);

	assert_int_equal(scion_bind(sock, (struct sockaddr *)&bound, sizeof(bound)), SCION_ERR_ALREADY_BOUND);
}

static void test_socket_bind_errors(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *first = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *second = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(first);
	struct sockaddr_in bound = bound_address(first);

	assert_int_equal(scion_bind(second, (struct sockaddr *)&bound, sizeof(bound)), SCION_ERR_ADDR_IN_USE);

	struct sockaddr_in6 addr6 = { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT };
	assert_int_equal(scion_bind(second, (struct sockaddr *)&addr6, sizeof(addr6)), SCION_ERR_ADDR_FAMILY_MISMATCH);

	struct sockaddr unknown_family = { .sa_family = AF_UNIX };
	assert_int_equal(scion_bind(second, &unknown_family, sizeof(unknown_family)), SCION_ERR_ADDR_FAMILY_UNKNOWN);
}

static void test_socket_options(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sock = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);

	// SCION_SO_DEBUG is handled by the library itself.
	bool debug = true;
	socklen_t len = sizeof(debug);
	assert_int_equal(scion_getsockopt(sock, SOL_SOCKET, SCION_SO_DEBUG, &debug, &len), 0);
	assert_false(debug);

	debug = true;
	assert_int_equal(scion_setsockopt(sock, SOL_SOCKET, SCION_SO_DEBUG, &debug, sizeof(debug)), 0);
	debug = false;
	assert_int_equal(scion_getsockopt(sock, SOL_SOCKET, SCION_SO_DEBUG, &debug, &len), 0);
	assert_true(debug);

	len = 0;
	assert_int_equal(scion_getsockopt(sock, SOL_SOCKET, SCION_SO_DEBUG, &debug, &len), SCION_ERR_BUF_TOO_SMALL);

	// Everything else is passed to the underlying socket.
	struct timeval timeout = { .tv_sec = 1, .tv_usec = 500000 };
	assert_int_equal(scion_setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), 0);
	struct timeval actual = { 0 };
	len = sizeof(actual);
	assert_int_equal(scion_getsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &actual, &len), 0);
	assert_int_equal(actual.tv_sec, 1);
	assert_int_equal(actual.tv_usec, 500000);

	int unknown_option = 0;
	len = sizeof(unknown_option);
	assert_int_equal(
		scion_getsockopt(sock, SOL_SOCKET, 9999, &unknown_option, &len), SCION_ERR_SOCK_OPT_INVALID);
}

static void test_socket_unsupported_flags(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sock = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sock);

	struct sockaddr_in dst = loopback_addr(30000);
	scion_ia local_ia = scion_topology_get_local_ia(fixture->topology);
	assert_int_equal(scion_sendto(sock, "x", 1, MSG_OOB, (struct sockaddr *)&dst, sizeof(dst), local_ia, NULL),
		SCION_ERR_FLAG_NOT_IMPLEMENTED);

	char buf[8];
	assert_int_equal(scion_recv(sock, buf, sizeof(buf), MSG_WAITALL), SCION_ERR_FLAG_NOT_IMPLEMENTED);
}

static void test_socket_send_without_destination(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sock = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);

	// Neither a destination address nor a connected socket.
	assert_int_equal(scion_sendto(sock, "x", 1, 0, NULL, 0, 0, NULL), SCION_ERR_NOT_CONNECTED);
}

static void test_socket_send_path_for_other_destination(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sock = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sock);

	scion_ia local_ia = scion_topology_get_local_ia(fixture->topology);
	struct scion_path path = { .src = local_ia, .dst = local_ia + 1, .path_type = SCION_PATH_TYPE_EMPTY };

	struct sockaddr_in dst = loopback_addr(30000);
	assert_int_equal(scion_sendto(sock, "x", 1, 0, (struct sockaddr *)&dst, sizeof(dst), local_ia, &path),
		SCION_ERR_DST_MISMATCH);
}

static void test_socket_connect_address_family_mismatch(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sock = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);

	// An IPv6 destination in an IPv4 network.
	struct sockaddr_in6 dst
		= { .sin6_family = AF_INET6, .sin6_addr = IN6ADDR_LOOPBACK_INIT, .sin6_port = htons(30000) };
	scion_ia local_ia = scion_topology_get_local_ia(fixture->topology);
	assert_int_equal(
		scion_connect(sock, (struct sockaddr *)&dst, sizeof(dst), local_ia), SCION_ERR_ADDR_FAMILY_MISMATCH);
}

int run_socket_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_socket_creation_errors, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_without_network, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_bind_and_getsockname, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_bind_errors, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_options, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_unsupported_flags, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_send_without_destination, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_send_path_for_other_destination, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_connect_address_family_mismatch, setup_fixture, teardown_fixture),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
