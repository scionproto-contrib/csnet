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
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "common/hop_field.h"
#include "common/info_field.h"
#include "common/isd_as.h"
#include "control_plane/network.h"
#include "control_plane/topology.h"
#include "data_plane/path.h"
#include "data_plane/socket.h"
#include "scion/scion.h"
#include "scion/scion_path.h"
#include "scion/scion_policy.h"
#include "socket_fixture.h"
#include "test_socket.h"
#include "util/list.h"

#ifdef __linux__
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#endif

#ifdef __linux__
// A buffer for the control message with the timestamps of the kernel. The union gives it the alignment of a control
// message header, which a plain char array does not guarantee.
union control_buffer {
	char buf[CMSG_SPACE(sizeof(struct scm_timestamping))];
	struct cmsghdr align;
};
#endif

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

static void count_policy_calls(struct scion_path_collection *paths, void *ctx)
{
	(void)paths;
	(*(int *)ctx)++;
}

static bool reject_path(struct scion_path *path, void *ctx)
{
	(void)path;
	(void)ctx;
	return false;
}

static void remove_all_paths(struct scion_path_collection *paths, void *ctx)
{
	(void)ctx;
	scion_path_collection_filter(paths, (struct scion_path_predicate){ .fn = reject_path });
}

static void test_socket_sendto_applies_the_policy(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sender = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *receiver = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(receiver);
	struct sockaddr_in receiver_addr = bound_address(receiver);

	int calls = 0;
	assert_int_equal(scion_setsockpolicy(sender, (struct scion_policy){ .fn = count_policy_calls, .ctx = &calls }), 0);

	assert_int_equal(scion_sendto(sender, "hello", 5, 0, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr),
						 local_ia_of(fixture), NULL),
		5);
	assert_int_equal(calls, 1);
}

static void test_socket_sendto_policy_removes_all_paths(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sender = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *receiver = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(receiver);
	struct sockaddr_in receiver_addr = bound_address(receiver);

	assert_int_equal(scion_setsockpolicy(sender, (struct scion_policy){ .fn = remove_all_paths, .ctx = NULL }), 0);

	assert_int_equal(scion_sendto(sender, "hello", 5, 0, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr),
						 local_ia_of(fixture), NULL),
		SCION_ERR_NO_PATHS);
}

static void test_socket_udp_round_trip(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sender = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *receiver = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sender);
	struct sockaddr_in sender_addr = bound_address(sender);
	bind_loopback(receiver);
	struct sockaddr_in receiver_addr = bound_address(receiver);
	set_receive_timeout(receiver, 1000);

	assert_int_equal(scion_sendto(sender, "hello", 5, 0, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr),
						 local_ia_of(fixture), NULL),
		5);

	char buf[16] = { 0 };
	struct sockaddr_in from;
	socklen_t from_len = sizeof(from);
	scion_ia from_ia = 0;
	struct scion_path *path = NULL;
	assert_int_equal(
		scion_recvfrom(receiver, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len, &from_ia, &path), 5);

	assert_memory_equal(buf, "hello", 5);
	assert_int_equal(from.sin_family, AF_INET);
	assert_uint_equal(ntohl(from.sin_addr.s_addr), INADDR_LOOPBACK);
	assert_int_equal(from.sin_port, sender_addr.sin_port);
	assert_true(from_ia == local_ia_of(fixture));
	assert_non_null(path);
	assert_int_equal(path->path_type, SCION_PATH_TYPE_EMPTY);

	scion_path_free(path);
}

static void test_socket_empty_payload(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sender = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *receiver = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sender);
	bind_loopback(receiver);
	struct sockaddr_in receiver_addr = bound_address(receiver);
	set_receive_timeout(receiver, 1000);

	assert_int_equal(scion_sendto(sender, "", 0, 0, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr),
						 local_ia_of(fixture), NULL),
		0);

	char buf[16];
	assert_int_equal(scion_recv(receiver, buf, sizeof(buf), 0), 0);
}

static void test_socket_receive_is_truncated_to_the_buffer(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sender = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *receiver = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sender);
	bind_loopback(receiver);
	struct sockaddr_in receiver_addr = bound_address(receiver);
	set_receive_timeout(receiver, 1000);

	assert_int_equal(scion_sendto(sender, "0123456789", 10, 0, (struct sockaddr *)&receiver_addr,
						 sizeof(receiver_addr), local_ia_of(fixture), NULL),
		10);

	char buf[4];
	assert_int_equal(scion_recv(receiver, buf, sizeof(buf), 0), 4);
	assert_memory_equal(buf, "0123", 4);
}

static void test_socket_receive_without_data_would_block(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sock = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sock);

	char buf[4];
	assert_int_equal(scion_recv(sock, buf, sizeof(buf), MSG_DONTWAIT), SCION_ERR_WOULD_BLOCK);

	set_receive_timeout(sock, 50);
	assert_int_equal(scion_recv(sock, buf, sizeof(buf), 0), SCION_ERR_WOULD_BLOCK);
}

static void test_socket_connected_round_trip(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *client = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *server = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(client);
	struct sockaddr_in client_addr = bound_address(client);
	bind_loopback(server);
	struct sockaddr_in server_addr = bound_address(server);
	set_receive_timeout(client, 1000);
	set_receive_timeout(server, 1000);

	scion_ia local_ia = local_ia_of(fixture);
	assert_int_equal(scion_connect(client, (struct sockaddr *)&server_addr, sizeof(server_addr), local_ia), 0);
	assert_int_equal(scion_connect(server, (struct sockaddr *)&client_addr, sizeof(client_addr), local_ia), 0);

	char buf[16] = { 0 };
	assert_int_equal(scion_send(client, "ping", 4, 0), 4);
	assert_int_equal(scion_recv(server, buf, sizeof(buf), 0), 4);
	assert_memory_equal(buf, "ping", 4);

	assert_int_equal(scion_send(server, "pong", 4, 0), 4);
	assert_int_equal(scion_recv(client, buf, sizeof(buf), 0), 4);
	assert_memory_equal(buf, "pong", 4);
}

static void test_socket_connected_ignores_other_senders(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *peer = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *stranger = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *server = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(peer);
	struct sockaddr_in peer_addr = bound_address(peer);
	bind_loopback(stranger);
	bind_loopback(server);
	struct sockaddr_in server_addr = bound_address(server);
	set_receive_timeout(server, 1000);

	assert_int_equal(scion_connect(server, (struct sockaddr *)&peer_addr, sizeof(peer_addr), local_ia_of(fixture)), 0);

	// The stranger's packet arrives first but must be skipped.
	assert_int_equal(scion_sendto(stranger, "stranger", 8, 0, (struct sockaddr *)&server_addr, sizeof(server_addr),
						 local_ia_of(fixture), NULL),
		8);
	assert_int_equal(scion_sendto(peer, "peer", 4, 0, (struct sockaddr *)&server_addr, sizeof(server_addr),
						 local_ia_of(fixture), NULL),
		4);

	char buf[16] = { 0 };
	assert_int_equal(scion_recv(server, buf, sizeof(buf), 0), 4);
	assert_memory_equal(buf, "peer", 4);
}

static void test_socket_scmp_echo_round_trip(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sender = open_socket(fixture, SCION_SOCK_RAW, SCION_PROTO_SCMP);
	struct scion_socket *receiver = open_socket(fixture, SCION_SOCK_RAW, SCION_PROTO_SCMP);
	bind_loopback(sender);
	bind_loopback(receiver);
	struct sockaddr_in receiver_addr = bound_address(receiver);
	set_receive_timeout(receiver, 1000);

	uint8_t data[] = { 1, 2, 3 };
	struct scion_scmp_echo echo
		= { .type = SCION_SCMP_TYPE_ECHO_REQUEST, .id = 7, .seqno = 3, .data = data, .data_length = sizeof(data) };
	uint8_t request[scion_scmp_echo_len(&echo)];
	assert_int_equal(scion_scmp_echo_serialize(&echo, request, sizeof(request)), 0);

	assert_int_equal(scion_sendto(sender, request, sizeof(request), 0, (struct sockaddr *)&receiver_addr,
						 sizeof(receiver_addr), local_ia_of(fixture), NULL),
		(ssize_t)sizeof(request));

	uint8_t buf[32];
	struct sockaddr_in from;
	socklen_t from_len = sizeof(from);
	assert_int_equal(scion_recvfrom(receiver, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len, NULL, NULL),
		(ssize_t)sizeof(request));

	struct scion_scmp_echo received;
	assert_int_equal(scion_scmp_echo_deserialize(buf, sizeof(request), &received), 0);
	assert_int_equal(received.type, SCION_SCMP_TYPE_ECHO_REQUEST);
	assert_uint_equal(received.id, 7);
	assert_uint_equal(received.seqno, 3);
	assert_uint_equal(received.data_length, sizeof(data));
	assert_memory_equal(received.data, data, sizeof(data));
	scion_scmp_echo_free_members(&received);

	// SCMP has no ports.
	assert_uint_equal(ntohl(from.sin_addr.s_addr), INADDR_LOOPBACK);
	assert_int_equal(from.sin_port, 0);
}

struct scmp_error_record {
	int calls;
	enum scion_scmp_type type;
	uint8_t code;
	uint16_t packet_length;
};

static void record_scmp_error(const struct scion_scmp_error *scmp_error, void *ctx)
{
	struct scmp_error_record *record = ctx;
	record->calls++;
	record->type = scmp_error->type;
	record->code = scmp_error->code;
	record->packet_length = scmp_error->packet_length;
}

// The automated version of the scmp_error and scmp_error_generator examples.
static void test_socket_scmp_error_calls_the_callback(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *generator = open_socket(fixture, SCION_SOCK_RAW, SCION_PROTO_SCMP);
	struct scion_socket *sock = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(generator);
	bind_loopback(sock);
	struct sockaddr_in sock_addr = bound_address(sock);
	set_receive_timeout(sock, 100);

	struct scmp_error_record record = { 0 };
	assert_int_equal(scion_setsockerrcb(sock, record_scmp_error, &record), 0);

	// Destination unreachable, code 4 (port unreachable), with two bytes of the offending packet.
	const uint8_t error[] = { 0x01, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xaa, 0xbb };
	assert_int_equal(scion_sendto(generator, error, sizeof(error), 0, (struct sockaddr *)&sock_addr, sizeof(sock_addr),
						 local_ia_of(fixture), NULL),
		(ssize_t)sizeof(error));

	// The error is not returned as data.
	char buf[16];
	assert_int_equal(scion_recv(sock, buf, sizeof(buf), 0), SCION_ERR_WOULD_BLOCK);

	assert_int_equal(record.calls, 1);
	assert_int_equal(record.type, 1);
	assert_int_equal(record.code, 4);
	assert_uint_equal(record.packet_length, 2);
}

static void test_socket_invalid_scmp_error_is_ignored(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *generator = open_socket(fixture, SCION_SOCK_RAW, SCION_PROTO_SCMP);
	struct scion_socket *sock = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(generator);
	bind_loopback(sock);
	struct sockaddr_in sock_addr = bound_address(sock);
	set_receive_timeout(sock, 100);

	struct scmp_error_record record = { 0 };
	assert_int_equal(scion_setsockerrcb(sock, record_scmp_error, &record), 0);

	// Type 3 is not defined, and the second message is too short for its type.
	const uint8_t unknown_type[] = { 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	const uint8_t too_short[] = { 0x01, 0x04, 0x00, 0x00 };
	const uint8_t *errors[] = { unknown_type, too_short };
	const size_t sizes[] = { sizeof(unknown_type), sizeof(too_short) };
	for (size_t i = 0; i < 2; i++) {
		assert_int_equal(scion_sendto(generator, errors[i], sizes[i], 0, (struct sockaddr *)&sock_addr,
							 sizeof(sock_addr), local_ia_of(fixture), NULL),
			(ssize_t)sizes[i]);

		char buf[16];
		assert_int_equal(scion_recv(sock, buf, sizeof(buf), 0), SCION_ERR_WOULD_BLOCK);
	}

	assert_int_equal(record.calls, 0);
}

static void test_socket_scmp_informational_message_is_not_an_error(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *generator = open_socket(fixture, SCION_SOCK_RAW, SCION_PROTO_SCMP);
	struct scion_socket *sock = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(generator);
	bind_loopback(sock);
	struct sockaddr_in sock_addr = bound_address(sock);
	set_receive_timeout(sock, 100);

	struct scmp_error_record record = { 0 };
	assert_int_equal(scion_setsockerrcb(sock, record_scmp_error, &record), 0);

	// An echo request is neither an error nor UDP, so a UDP socket skips it.
	const uint8_t echo[] = { 0x80, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01 };
	assert_int_equal(scion_sendto(generator, echo, sizeof(echo), 0, (struct sockaddr *)&sock_addr, sizeof(sock_addr),
						 local_ia_of(fixture), NULL),
		(ssize_t)sizeof(echo));

	char buf[16];
	assert_int_equal(scion_recv(sock, buf, sizeof(buf), 0), SCION_ERR_WOULD_BLOCK);
	assert_int_equal(record.calls, 0);
}

// Builds a path of two hop fields, from this AS through interface 11 to a neighbor entered through interface 12.
static void init_two_hop_path(struct scion_path *path, struct scion_path_raw *raw_path, uint8_t *buf,
	struct sockaddr_in next_hop, scion_ia ia)
{
	struct scion_path_meta_hdr hdr = { .seg_len = { 2, 0, 0 } };
	struct scion_info_field info = { .cons_dir = true };
	struct scion_hop_field hops[2] = { { .exp_time = 63, .cons_egress = 11 }, { .exp_time = 63, .cons_ingress = 12 } };

	struct scion_list *info_fields = scion_list_create(SCION_LIST_NO_FREE_VALUES);
	struct scion_list *hop_fields = scion_list_create(SCION_LIST_NO_FREE_VALUES);
	scion_list_append(info_fields, &info);
	scion_list_append(hop_fields, &hops[0]);
	scion_list_append(hop_fields, &hops[1]);
	assert_int_equal(scion_path_serialize(&hdr, info_fields, hop_fields, buf), 0);
	scion_list_free(info_fields);
	scion_list_free(hop_fields);

	raw_path->raw = buf;
	raw_path->length = SCION_META_LEN + SCION_INFO_LEN + 2 * SCION_HOP_LEN;

	*path = (struct scion_path) { .src = ia, .dst = ia, .path_type = SCION_PATH_TYPE_SCION, .raw_path = raw_path };
	memcpy(&path->underlay_next_hop.addr, &next_hop, sizeof(next_hop));
	path->underlay_next_hop.addrlen = sizeof(next_hop);
	path->underlay_next_hop.addr_family = SCION_AF_INET;
}

// A traceroute as the command does it, with a socket that plays the border router.
static void test_socket_traceroute_with_router_alert(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *tracer = open_socket(fixture, SCION_SOCK_RAW, SCION_PROTO_SCMP);
	struct scion_socket *router = open_socket(fixture, SCION_SOCK_RAW, SCION_PROTO_SCMP);
	bind_loopback(tracer);
	bind_loopback(router);
	struct sockaddr_in tracer_addr = bound_address(tracer);
	struct sockaddr_in router_addr = bound_address(router);
	set_receive_timeout(tracer, 1000);
	set_receive_timeout(router, 1000);

	scion_ia ia = local_ia_of(fixture);
	uint8_t raw[SCION_META_LEN + SCION_INFO_LEN + 2 * SCION_HOP_LEN];
	struct scion_path_raw raw_path;
	struct scion_path path;
	init_two_hop_path(&path, &raw_path, raw, router_addr, ia);

	for (size_t interface_index = 0; interface_index < 2; interface_index++) {
		// Request, the router alert is set for one interface
		assert_int_equal(scion_path_set_router_alert(&path, interface_index), 0);
		struct scion_scmp_traceroute request = { .type = SCION_SCMP_TYPE_TRACEROUTE_REQUEST,
			.id = ntohs(tracer_addr.sin_port),
			.seqno = (uint16_t)interface_index };
		uint8_t buf[SCION_SCMP_TRACEROUTE_LEN];
		assert_int_equal(scion_scmp_traceroute_serialize(&request, buf, sizeof(buf)), 0);
		assert_int_equal(scion_sendto(tracer, buf, sizeof(buf), 0, (struct sockaddr *)&router_addr,
							 sizeof(router_addr), ia, &path),
			(ssize_t)sizeof(buf));

		// The router sees the request and the path with the flag
		struct scion_path *received_path;
		struct sockaddr_in from;
		socklen_t from_len = sizeof(from);
		assert_int_equal(scion_recvfrom(router, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len, NULL,
							 &received_path),
			(ssize_t)sizeof(buf));

		struct scion_scmp_traceroute received;
		assert_int_equal(scion_scmp_traceroute_deserialize(buf, sizeof(buf), &received), 0);
		assert_int_equal(received.type, SCION_SCMP_TYPE_TRACEROUTE_REQUEST);
		assert_uint_equal(received.id, ntohs(tracer_addr.sin_port));
		assert_uint_equal(received.seqno, interface_index);

		struct scion_path_meta_hdr hdr;
		struct scion_list *info_fields = scion_list_create(SCION_LIST_SIMPLE_FREE);
		struct scion_list *hop_fields = scion_list_create(SCION_LIST_SIMPLE_FREE);
		assert_int_equal(scion_path_deserialize(received_path->raw_path->raw, received_path->raw_path->length, &hdr,
							 info_fields, hop_fields),
			0);
		struct scion_hop_field *first = scion_list_get(hop_fields, 0);
		struct scion_hop_field *second = scion_list_get(hop_fields, 1);
		// Interface 11 is left through the egress interface of the first hop field, 12 is entered through the
		// ingress interface of the second one.
		assert_int_equal(first->egress_router_alert, interface_index == 0);
		assert_false(first->ingress_router_alert);
		assert_int_equal(second->ingress_router_alert, interface_index == 1);
		assert_false(second->egress_router_alert);
		scion_list_free(info_fields);
		scion_list_free(hop_fields);
		scion_path_free(received_path);

		// The router answers, the socket accepts the reply although it does not come from the destination
		struct scion_scmp_traceroute reply = { .type = SCION_SCMP_TYPE_TRACEROUTE_REPLY,
			.id = received.id,
			.seqno = received.seqno,
			.ia = ia,
			.interface = interface_index == 0 ? 11 : 12 };
		assert_int_equal(scion_scmp_traceroute_serialize(&reply, buf, sizeof(buf)), 0);
		assert_int_equal(scion_sendto(router, buf, sizeof(buf), 0, (struct sockaddr *)&tracer_addr,
							 sizeof(tracer_addr), ia, NULL),
			(ssize_t)sizeof(buf));

		from_len = sizeof(from);
		assert_int_equal(
			scion_recvfrom(tracer, buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len, NULL, NULL),
			(ssize_t)sizeof(buf));
		assert_int_equal(scion_scmp_traceroute_deserialize(buf, sizeof(buf), &received), 0);
		assert_int_equal(received.type, SCION_SCMP_TYPE_TRACEROUTE_REPLY);
		assert_uint_equal(received.seqno, interface_index);
		assert_true(received.ia == ia);
		assert_uint_equal(received.interface, interface_index == 0 ? 11 : 12);
		assert_uint_equal(ntohl(from.sin_addr.s_addr), INADDR_LOOPBACK);
	}
}

#ifdef __linux__
static void test_socket_receive_no_control_messages(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sender = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *receiver = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sender);
	bind_loopback(receiver);
	struct sockaddr_in receiver_addr = bound_address(receiver);
	set_receive_timeout(receiver, 1000);

	assert_int_equal(scion_sendto(sender, "x", 1, 0, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr),
						 local_ia_of(fixture), NULL),
		1);

	char buf[16];
	union control_buffer control;
	struct iovec iov = { .iov_base = buf, .iov_len = sizeof(buf) };
	struct msghdr msg
		= { .msg_iov = &iov, .msg_iovlen = 1, .msg_control = control.buf, .msg_controllen = sizeof(control.buf) };
	assert_int_equal(scion_recvmsg(receiver, &msg, 0, NULL, NULL), 1);
	assert_int_equal(msg.msg_controllen, 0);
}

// Finds the timestamps in the control messages of a received message.
static struct scm_timestamping find_timestamps(struct msghdr *msg)
{
	for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(msg); cmsg != NULL; cmsg = CMSG_NXTHDR(msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_TIMESTAMPING) {
			struct scm_timestamping timestamps;
			assert_true(cmsg->cmsg_len >= CMSG_LEN(sizeof(timestamps)));
			memcpy(&timestamps, CMSG_DATA(cmsg), sizeof(timestamps));
			return timestamps;
		}
	}

	fail_msg("no SCM_TIMESTAMPING control message");
	return (struct scm_timestamping) { 0 };
}

static void test_socket_receive_error_queue(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sender = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *receiver = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sender);
	bind_loopback(receiver);
	struct sockaddr_in receiver_addr = bound_address(receiver);
	set_receive_timeout(sender, 1000);

	int timestamping = SOF_TIMESTAMPING_TX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;
	assert_int_equal(scion_setsockopt(sender, SOL_SOCKET, SO_TIMESTAMPING, &timestamping, sizeof(timestamping)), 0);

	assert_int_equal(scion_sendto(sender, "x", 1, 0, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr),
						 local_ia_of(fixture), NULL),
		1);

	// The buffer has room for the timestamp only, the error message that comes with it is cut off.
	union control_buffer control;
	struct msghdr msg = { .msg_control = control.buf, .msg_controllen = sizeof(control.buf) };
	assert_int_equal(scion_recvmsg(sender, &msg, MSG_ERRQUEUE, NULL, NULL), 0);

	struct scm_timestamping timestamps = find_timestamps(&msg);
	assert_true(timestamps.ts[0].tv_sec > 0);
}

static void test_socket_send_control_message(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sender = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *receiver = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sender);
	bind_loopback(receiver);
	struct sockaddr_in receiver_addr = bound_address(receiver);

	// The control messages of the underlying socket have no meaning for a SCION socket.
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} control;
	char data[] = "x";
	struct iovec iov = { .iov_base = data, .iov_len = 1 };
	struct msghdr msg = { .msg_name = &receiver_addr,
		.msg_namelen = sizeof(receiver_addr),
		.msg_iov = &iov,
		.msg_iovlen = 1,
		.msg_control = control.buf,
		.msg_controllen = sizeof(control.buf) };
	int tos = 0;
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = IPPROTO_IP;
	cmsg->cmsg_type = IP_TOS;
	cmsg->cmsg_len = CMSG_LEN(sizeof(tos));
	memcpy(CMSG_DATA(cmsg), &tos, sizeof(tos));

	assert_int_equal(scion_sendmsg(sender, &msg, 0, local_ia_of(fixture), NULL), SCION_ERR_CONTROL_MSG_NOT_IMPLEMENTED);
}

// Receives a packet with the options for the control messages of the underlying socket set on the receiver.
static void receive_with_control_messages(struct socket_fixture *fixture, int timestamping, struct msghdr *msg,
	struct iovec *iov, char *buf, size_t buf_len, char *control, size_t control_len)
{
	struct scion_socket *sender = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *receiver = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sender);
	bind_loopback(receiver);
	set_receive_timeout(receiver, 1000);
	struct sockaddr_in receiver_addr = bound_address(receiver);

	// The underlying socket returns the destination address of the packet in a control message.
	int on = 1;
	assert_int_equal(scion_setsockopt(receiver, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)), 0);
	if (timestamping != 0) {
		assert_int_equal(
			scion_setsockopt(receiver, SOL_SOCKET, SO_TIMESTAMPING, &timestamping, sizeof(timestamping)), 0);
		wait_for_kernel_timestamping();
	}

	assert_int_equal(scion_sendto(sender, "x", 1, 0, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr),
						 local_ia_of(fixture), NULL),
		1);

	*iov = (struct iovec) { .iov_base = buf, .iov_len = buf_len };
	*msg = (struct msghdr) { .msg_iov = iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = control_len };
	assert_int_equal(scion_recvmsg(receiver, msg, 0, NULL, NULL), 1);
}

static void test_socket_receive_drops_control_messages(void **state)
{
	struct msghdr msg;
	struct iovec iov;
	char buf[16];
	union {
		char buf[256];
		struct cmsghdr align;
	} control;
	receive_with_control_messages(*state, 0, &msg, &iov, buf, sizeof(buf), control.buf, sizeof(control.buf));

	assert_int_equal(msg.msg_controllen, 0);
}

static void test_socket_receive_keeps_the_timestamps(void **state)
{
	struct msghdr msg;
	struct iovec iov;
	char buf[16];
	union {
		char buf[256];
		struct cmsghdr align;
	} control;
	receive_with_control_messages(*state, SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE, &msg, &iov, buf,
		sizeof(buf), control.buf, sizeof(control.buf));

	// The timestamps are the only control message that remains.
	assert_int_equal(msg.msg_controllen, CMSG_SPACE(sizeof(struct scm_timestamping)));
	struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
	assert_non_null(cmsg);
	assert_int_equal(cmsg->cmsg_level, SOL_SOCKET);
	assert_int_equal(cmsg->cmsg_type, SCM_TIMESTAMPING);
	assert_null(CMSG_NXTHDR(&msg, cmsg));
}

static void test_socket_receive_empty_error_queue(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sock = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sock);

	union control_buffer control;
	struct msghdr msg = { .msg_control = control.buf, .msg_controllen = sizeof(control.buf) };
	assert_int_equal(scion_recvmsg(sock, &msg, MSG_ERRQUEUE | MSG_DONTWAIT, NULL, NULL), SCION_ERR_WOULD_BLOCK);
}
#endif

static int count_open_file_descriptors(void)
{
	int count = 0;
	for (int fd = 0; fd < 1024; fd++) {
		if (fcntl(fd, F_GETFD) != -1) {
			count++;
		}
	}
	return count;
}

static void test_socket_creation_failure_does_not_leak_the_descriptor(void **state)
{
	struct socket_fixture *fixture = *state;

	// Without a border router, scion_socket fails after it has created the underlying socket.
	scion_list_free(fixture->topology->border_routers);
	fixture->topology->border_routers = scion_list_create(SCION_LIST_CUSTOM_FREE(free_test_border_router));

	int open_before = count_open_file_descriptors();
	struct scion_socket *sock;
	assert_int_equal(scion_socket(&sock, SCION_AF_INET, SCION_SOCK_DGRAM, SCION_PROTO_UDP, fixture->network),
		SCION_ERR_TOPOLOGY_INVALID);
	assert_int_equal(count_open_file_descriptors(), open_before);
}

// A SCION packet with an empty path, a UDP next header and a 3 byte payload.
// clang-format off
static const uint8_t well_formed_packet[] = {
	0x00, 0x00, 0x00, 0x01, 0x11, 0x09, 0x00, 0x03,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x01, 0xff, 0x00, 0x00, 0x00, 0x01, 0x21,
	0x00, 0x02, 0xff, 0x00, 0x00, 0x00, 0x02, 0x21,
	0x7f, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
	0x61, 0x62, 0x63,
};
// clang-format on

#define WELL_FORMED_HDR_LEN 36

// Sends raw bytes to the underlying socket, as any host that can reach the port could.
static void inject_packet(const struct sockaddr_in *to, const uint8_t *packet, size_t length)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert_true(fd >= 0);
	ssize_t sent = sendto(fd, packet, length, 0, (const struct sockaddr *)to, sizeof(*to));
	close(fd);
	assert_int_equal(sent, (ssize_t)length);
}

static void test_socket_receive_skips_malformed_packets(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sender = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *receiver = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sender);
	bind_loopback(receiver);
	struct sockaddr_in receiver_addr = bound_address(receiver);
	set_receive_timeout(receiver, 100);

	// Shorter than the common header.
	inject_packet(&receiver_addr, well_formed_packet, 5);

	// The address header is cut off.
	inject_packet(&receiver_addr, well_formed_packet, 27);

	// The payload is shorter than announced.
	inject_packet(&receiver_addr, well_formed_packet, sizeof(well_formed_packet) - 1);

	// The hdr_len is shorter than the headers.
	uint8_t bad_hdr_len[sizeof(well_formed_packet)];
	memcpy(bad_hdr_len, well_formed_packet, sizeof(bad_hdr_len));
	bad_hdr_len[5] = (WELL_FORMED_HDR_LEN - 4) / 4;
	inject_packet(&receiver_addr, bad_hdr_len, sizeof(bad_hdr_len));

	// An empty path with a path header.
	uint8_t extra_path_header[sizeof(well_formed_packet) + 4];
	memcpy(extra_path_header, well_formed_packet, WELL_FORMED_HDR_LEN);
	extra_path_header[5] = (WELL_FORMED_HDR_LEN + 4) / 4;
	memset(&extra_path_header[WELL_FORMED_HDR_LEN], 0xff, 4);
	memcpy(&extra_path_header[WELL_FORMED_HDR_LEN + 4], "abc", 3);
	inject_packet(&receiver_addr, extra_path_header, sizeof(extra_path_header));

	// All of them are skipped.
	char buf[16];
	assert_int_equal(scion_recv(receiver, buf, sizeof(buf), 0), SCION_ERR_WOULD_BLOCK);

	// The socket keeps working.
	assert_int_equal(scion_sendto(sender, "ok", 2, 0, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr),
						 local_ia_of(fixture), NULL),
		2);
	assert_int_equal(scion_recv(receiver, buf, sizeof(buf), 0), 2);
	assert_memory_equal(buf, "ok", 2);
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
		cmocka_unit_test_setup_teardown(test_socket_udp_round_trip, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_sendto_applies_the_policy, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_sendto_policy_removes_all_paths, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_empty_payload, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(
			test_socket_receive_is_truncated_to_the_buffer, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_receive_without_data_would_block, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_connected_round_trip, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_connected_ignores_other_senders, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_scmp_echo_round_trip, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_scmp_error_calls_the_callback, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_invalid_scmp_error_is_ignored, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(
			test_socket_scmp_informational_message_is_not_an_error, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_traceroute_with_router_alert, setup_fixture, teardown_fixture),
#ifdef __linux__
		cmocka_unit_test_setup_teardown(test_socket_receive_no_control_messages, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_receive_error_queue, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_receive_empty_error_queue, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_send_control_message, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_receive_drops_control_messages, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_receive_keeps_the_timestamps, setup_fixture, teardown_fixture),
#endif
		cmocka_unit_test_setup_teardown(
			test_socket_creation_failure_does_not_leak_the_descriptor, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_socket_receive_skips_malformed_packets, setup_fixture, teardown_fixture),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
