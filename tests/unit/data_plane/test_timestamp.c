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

#include <cmocka.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/errqueue.h>
#include <linux/net_tstamp.h>
#endif

#include "scion/scion.h"
#include "scion/scion_timestamp.h"
#include "socket_fixture.h"
#include "test_timestamp.h"

#ifdef __linux__
// A buffer for the control message with the timestamps of the kernel. The union gives it the alignment of a control
// message header, which a plain char array does not guarantee.
union control_buffer {
	char buf[CMSG_SPACE(sizeof(struct scm_timestamping))];
	struct cmsghdr align;
};
#endif

// Sends a packet from one socket to another and receives it with the control messages. The message is returned with
// its control buffer in the given storage.
static void send_and_receive(struct socket_fixture *fixture, struct scion_socket *sender,
	struct scion_socket *receiver, struct msghdr *msg, struct iovec *iov, char *buf, size_t buf_len, char *control,
	size_t control_len)
{
	struct sockaddr_in receiver_addr = bound_address(receiver);
	assert_int_equal(scion_sendto(sender, "x", 1, 0, (struct sockaddr *)&receiver_addr, sizeof(receiver_addr),
						 local_ia_of(fixture), NULL),
		1);

	*iov = (struct iovec) { .iov_base = buf, .iov_len = buf_len };
	*msg = (struct msghdr) { .msg_iov = iov, .msg_iovlen = 1, .msg_control = control, .msg_controllen = control_len };
	assert_int_equal(scion_recvmsg(receiver, msg, 0, NULL, NULL), 1);
}

static struct timespec current_time(void)
{
	struct timespec now;
	assert_int_equal(clock_gettime(CLOCK_REALTIME, &now), 0);
	return now;
}

static bool is_not_before(const struct timespec *time, const struct timespec *other)
{
	return time->tv_sec > other->tv_sec || (time->tv_sec == other->tv_sec && time->tv_nsec >= other->tv_nsec);
}

// Checks that a timestamp was taken between two readings of the clock.
static void assert_taken_between(
	const struct timespec *time, const struct timespec *before, const struct timespec *after)
{
	assert_true(is_not_before(time, before));
	assert_true(is_not_before(after, time));
}

static void test_receive_timestamp_without_the_kernel(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sender = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *receiver = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sender);
	bind_loopback(receiver);
	set_receive_timeout(receiver, 1000);

	struct msghdr msg;
	struct iovec iov;
	char buf[16];
	struct timespec before = current_time();
	send_and_receive(fixture, sender, receiver, &msg, &iov, buf, sizeof(buf), NULL, 0);

	// The kernel did not provide a timestamp, so the time is taken in user space.
	struct scion_timestamp timestamp;
	assert_int_equal(scion_timestamp_get_rx(receiver, &msg, &timestamp), 0);
	struct timespec after = current_time();
	assert_int_equal(timestamp.level, SCION_TIMESTAMP_USER);
	assert_taken_between(&timestamp.time, &before, &after);
}

#ifdef __linux__
static void test_receive_timestamp_of_the_kernel(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sender = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *receiver = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sender);
	bind_loopback(receiver);
	set_receive_timeout(receiver, 1000);

	int timestamping = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE;
	assert_int_equal(scion_setsockopt(receiver, SOL_SOCKET, SO_TIMESTAMPING, &timestamping, sizeof(timestamping)), 0);
	wait_for_kernel_timestamping();

	struct msghdr msg;
	struct iovec iov;
	char buf[16];
	union control_buffer control;
	struct timespec before = current_time();
	send_and_receive(fixture, sender, receiver, &msg, &iov, buf, sizeof(buf), control.buf, sizeof(control.buf));

	struct scion_timestamp timestamp;
	assert_int_equal(scion_timestamp_get_rx(receiver, &msg, &timestamp), 0);
	struct timespec after = current_time();
	assert_int_equal(timestamp.level, SCION_TIMESTAMP_KERNEL);
	assert_taken_between(&timestamp.time, &before, &after);
}

static void test_receive_timestamp_of_the_hardware_flags(void **state)
{
	struct socket_fixture *fixture = *state;
	struct scion_socket *sender = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	struct scion_socket *receiver = open_socket(fixture, SCION_SOCK_DGRAM, SCION_PROTO_UDP);
	bind_loopback(sender);
	bind_loopback(receiver);
	set_receive_timeout(receiver, 1000);

	// The kernel accepts the flags without a network card that supports them, and still gives the system clock.
	int timestamping = SOF_TIMESTAMPING_SOFTWARE | SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_RAW_HARDWARE
					   | SOF_TIMESTAMPING_RX_HARDWARE;
	assert_int_equal(scion_setsockopt(receiver, SOL_SOCKET, SO_TIMESTAMPING, &timestamping, sizeof(timestamping)), 0);
	wait_for_kernel_timestamping();

	struct msghdr msg;
	struct iovec iov;
	char buf[16];
	union control_buffer control;
	send_and_receive(fixture, sender, receiver, &msg, &iov, buf, sizeof(buf), control.buf, sizeof(control.buf));

	struct scion_timestamp timestamp;
	assert_int_equal(scion_timestamp_get_rx(receiver, &msg, &timestamp), 0);
	assert_int_equal(timestamp.level, SCION_TIMESTAMP_KERNEL);
}
#endif

int run_timestamp_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test_setup_teardown(test_receive_timestamp_without_the_kernel, setup_fixture, teardown_fixture),
#ifdef __linux__
		cmocka_unit_test_setup_teardown(test_receive_timestamp_of_the_kernel, setup_fixture, teardown_fixture),
		cmocka_unit_test_setup_teardown(test_receive_timestamp_of_the_hardware_flags, setup_fixture, teardown_fixture),
#endif
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
