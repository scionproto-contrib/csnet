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
#include <sys/wait.h>
#include <unistd.h>

#include "common/isd_as.h"
#include "common/path_segment.h"
#include "control_plane/segment.h"
#include "control_plane/topology.h"
#include "scion/scion.h"
#include "test_segment.h"

static scion_ia parse_ia(const char *str)
{
	scion_ia ia;
	assert_int_equal(scion_ia_parse(str, strlen(str), &ia), 0);
	return ia;
}

static void assert_split_seg(const struct scion_split_segments *actual, const struct scion_split_segments *expected)
{
	assert_int_equal(actual->has_up, expected->has_up);
	if (expected->has_up) {
		assert_true(actual->up_src == expected->up_src);
		assert_true(actual->up_dst == expected->up_dst);
	}

	assert_int_equal(actual->has_core, expected->has_core);
	if (expected->has_core) {
		assert_true(actual->core_src == expected->core_src);
		assert_true(actual->core_dst == expected->core_dst);
	}

	assert_int_equal(actual->has_down, expected->has_down);
	if (expected->has_down) {
		assert_true(actual->down_src == expected->down_src);
		assert_true(actual->down_dst == expected->down_dst);
	}
}

// Case (1): source and destination are the same AS - no segments needed.
static void test_split_segments_same_as(void **)
{
	scion_ia as = parse_ia("1-ff00:0:110");

	struct scion_split_segments actual;
	assert_int_equal(scion_split_segments(as, false, as, false, &actual), 0);

	struct scion_split_segments expected = { 0 };
	assert_split_seg(&actual, &expected);
}

// Case (2): both ASes are core, regardless of ISD - a single CORE segment.
static void test_split_segments_both_core(void **)
{
	scion_ia src = parse_ia("1-ff00:0:110");
	scion_ia dst = parse_ia("1-ff00:0:120");

	struct scion_split_segments actual;
	assert_int_equal(scion_split_segments(src, true, dst, true, &actual), 0);

	struct scion_split_segments expected = {
		.has_core = true, .core_src = src, .core_dst = dst,
	};
	assert_split_seg(&actual, &expected);
}

// Case (3): same ISD, only the source is core - CORE then DOWN.
static void test_split_segments_same_isd_src_core(void **)
{
	scion_ia src = parse_ia("1-ff00:0:110");
	scion_ia dst = parse_ia("1-ff00:0:120");
	scion_ia wildcard = scion_ia_to_wildcard(src);

	struct scion_split_segments actual;
	assert_int_equal(scion_split_segments(src, true, dst, false, &actual), 0);

	struct scion_split_segments expected = {
		.has_core = true, .core_src = src, .core_dst = wildcard,
		.has_down = true, .down_src = wildcard, .down_dst = dst,
	};
	assert_split_seg(&actual, &expected);
}

// Case (4): same ISD, only the destination is core - UP then CORE.
static void test_split_segments_same_isd_dst_core(void **)
{
	scion_ia src = parse_ia("1-ff00:0:110");
	scion_ia dst = parse_ia("1-ff00:0:120");
	scion_ia wildcard = scion_ia_to_wildcard(src);

	struct scion_split_segments actual;
	assert_int_equal(scion_split_segments(src, false, dst, true, &actual), 0);

	struct scion_split_segments expected = {
		.has_up = true, .up_src = src, .up_dst = wildcard,
		.has_core = true, .core_src = wildcard, .core_dst = dst,
	};
	assert_split_seg(&actual, &expected);
}

// Case (5): same ISD, neither is core - UP, CORE, then DOWN.
static void test_split_segments_same_isd_neither_core(void **)
{
	scion_ia src = parse_ia("1-ff00:0:110");
	scion_ia dst = parse_ia("1-ff00:0:120");
	scion_ia wildcard = scion_ia_to_wildcard(src);

	struct scion_split_segments actual;
	assert_int_equal(scion_split_segments(src, false, dst, false, &actual), 0);

	struct scion_split_segments expected = {
		.has_up = true, .up_src = src, .up_dst = wildcard,
		.has_core = true, .core_src = wildcard, .core_dst = wildcard,
		.has_down = true, .down_src = wildcard, .down_dst = dst,
	};
	assert_split_seg(&actual, &expected);
}

// Case (6): different ISDs, only the source is core - CORE then DOWN, bounded by the destination ISD's wildcard.
static void test_split_segments_diff_isd_src_core(void **)
{
	scion_ia src = parse_ia("1-ff00:0:110");
	scion_ia dst = parse_ia("2-ff00:0:220");
	scion_ia dst_wildcard = scion_ia_to_wildcard(dst);

	struct scion_split_segments actual;
	assert_int_equal(scion_split_segments(src, true, dst, false, &actual), 0);

	struct scion_split_segments expected = {
		.has_core = true, .core_src = src, .core_dst = dst_wildcard,
		.has_down = true, .down_src = dst_wildcard, .down_dst = dst,
	};
	assert_split_seg(&actual, &expected);
}

// Case (7): different ISDs, only the destination is core - UP then CORE, bounded by the source ISD's wildcard.
static void test_split_segments_diff_isd_dst_core(void **)
{
	scion_ia src = parse_ia("1-ff00:0:110");
	scion_ia dst = parse_ia("2-ff00:0:220");
	scion_ia src_wildcard = scion_ia_to_wildcard(src);

	struct scion_split_segments actual;
	assert_int_equal(scion_split_segments(src, false, dst, true, &actual), 0);

	struct scion_split_segments expected = {
		.has_up = true, .up_src = src, .up_dst = src_wildcard,
		.has_core = true, .core_src = src_wildcard, .core_dst = dst,
	};
	assert_split_seg(&actual, &expected);
}

// Case (8): different ISDs, neither is core - UP, CORE, then DOWN, each bounded by its own ISD's wildcard.
static void test_split_segments_diff_isd_neither_core(void **)
{
	scion_ia src = parse_ia("1-ff00:0:110");
	scion_ia dst = parse_ia("2-ff00:0:220");
	scion_ia src_wildcard = scion_ia_to_wildcard(src);
	scion_ia dst_wildcard = scion_ia_to_wildcard(dst);

	struct scion_split_segments actual;
	assert_int_equal(scion_split_segments(src, false, dst, false, &actual), 0);

	struct scion_split_segments expected = {
		.has_up = true, .up_src = src, .up_dst = src_wildcard,
		.has_core = true, .core_src = src_wildcard, .core_dst = dst_wildcard,
		.has_down = true, .down_src = dst_wildcard, .down_dst = dst,
	};
	assert_split_seg(&actual, &expected);
}

static struct scion_path_segment *make_empty_segment(void)
{
	struct scion_path_segment *seg = calloc(1, sizeof(*seg));
	return seg;
}

static void test_free_pathseglist_internal(void **)
{
	struct scion_path_segment_list list;
	list.length = 2;
	list.list = malloc(list.length * sizeof(*list.list));
	list.list[0] = make_empty_segment();
	list.list[1] = make_empty_segment();

	scion_free_pathseglist_internal(&list);
}

static void test_pathsegment_list_byte_size(void **)
{
	struct scion_path_segment_list list;
	list.length = 2;
	list.list = malloc(list.length * sizeof(*list.list));
	list.list[0] = make_empty_segment();
	list.list[1] = make_empty_segment();

	size_t expected
		= sizeof(list) + list.length * sizeof(struct scion_path_segment *) + list.length * sizeof(*list.list[0]);
	assert_int_equal(scion_pathsegment_list_byte_size(&list), expected);

	scion_free_pathseglist_internal(&list);
}

// Starts listening on a free port of the loopback interface.
static int listen_on_loopback(struct sockaddr_in *addr)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	assert_true(fd >= 0);

	memset(addr, 0, sizeof(*addr));
	addr->sin_family = AF_INET;
	addr->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	assert_int_equal(bind(fd, (struct sockaddr *)addr, sizeof(*addr)), 0);
	assert_int_equal(listen(fd, 1), 0);

	socklen_t addr_len = sizeof(*addr);
	assert_int_equal(getsockname(fd, (struct sockaddr *)addr, &addr_len), 0);
	return fd;
}

static void set_control_service(struct scion_topology *topology, const struct sockaddr_in *addr)
{
	memset(topology, 0, sizeof(*topology));
	memcpy(&topology->cs_addr, addr, sizeof(*addr));
	topology->cs_addr_len = sizeof(*addr);
}

// Starts a control service in a child process that answers two connections with the reply (if any) and closes them.
static pid_t start_control_service(int listen_fd, const char *reply)
{
	pid_t pid = fork();
	assert_true(pid >= 0);
	if (pid == 0) {
		for (int i = 0; i < 2; i++) {
			int fd = accept(listen_fd, NULL, NULL);
			if (fd >= 0 && reply != NULL) {
				(void)write(fd, reply, strlen(reply));
			}
			if (fd >= 0) {
				close(fd);
			}
		}
		_exit(0);
	}
	return pid;
}

// Both requests to the control service fail with the expected error.
static void assert_requests_fail(const struct sockaddr_in *addr, int expected)
{
	struct scion_topology topology;
	set_control_service(&topology, addr);
	scion_ia src = parse_ia("1-ff00:0:111");
	scion_ia dst = parse_ia("1-ff00:0:112");

	struct scion_path_segment_list segments;
	assert_int_equal(scion_path_segments_lookup(&topology, src, dst, &segments), expected);
	assert_int_equal(scion_dst_core_check(&topology, src, dst), expected);
}

static void test_requests_control_service_not_reachable(void **)
{
	// Nothing listens on the port after the listening socket is closed.
	struct sockaddr_in addr;
	close(listen_on_loopback(&addr));

	assert_requests_fail(&addr, SCION_ERR_CONTROL_SERVICE_CONNECT_FAIL);
}

static void test_requests_control_service_closes_connection(void **)
{
	struct sockaddr_in addr;
	int listen_fd = listen_on_loopback(&addr);

	pid_t pid = start_control_service(listen_fd, NULL);
	assert_requests_fail(&addr, SCION_ERR_CONTROL_SERVICE_REQUEST_FAIL);
	waitpid(pid, NULL, 0);
	close(listen_fd);
}

static void test_requests_control_service_sends_garbage(void **)
{
	struct sockaddr_in addr;
	int listen_fd = listen_on_loopback(&addr);

	const char *reply = "this is not http/2, it is some plain text of a server";
	pid_t pid = start_control_service(listen_fd, reply);
	assert_requests_fail(&addr, SCION_ERR_CONTROL_SERVICE_REQUEST_FAIL);
	waitpid(pid, NULL, 0);
	close(listen_fd);
}

int run_segment_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_split_segments_same_as),
		cmocka_unit_test(test_split_segments_both_core),
		cmocka_unit_test(test_split_segments_same_isd_src_core),
		cmocka_unit_test(test_split_segments_same_isd_dst_core),
		cmocka_unit_test(test_split_segments_same_isd_neither_core),
		cmocka_unit_test(test_split_segments_diff_isd_src_core),
		cmocka_unit_test(test_split_segments_diff_isd_dst_core),
		cmocka_unit_test(test_split_segments_diff_isd_neither_core),
		cmocka_unit_test(test_free_pathseglist_internal),
		cmocka_unit_test(test_pathsegment_list_byte_size),
		cmocka_unit_test(test_requests_control_service_not_reachable),
		cmocka_unit_test(test_requests_control_service_closes_connection),
		cmocka_unit_test(test_requests_control_service_sends_garbage),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
