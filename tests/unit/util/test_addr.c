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
#include <string.h>

#include "test_addr.h"
#include "util/addr.h"

static void test_parse_ipv4(void **)
{
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	scion_ia ia;

	assert_int_equal(scion_addr_parse("1-ff00:0:133,127.0.0.100", 30041, &ia, (struct sockaddr *)&addr, &addr_len), 0);

	scion_ia expected_ia;
	assert_int_equal(scion_ia_parse("1-ff00:0:133", strlen("1-ff00:0:133"), &expected_ia), 0);
	assert_true(ia == expected_ia);

	struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
	assert_int_equal(addr_in->sin_family, AF_INET);
	assert_int_equal(ntohs(addr_in->sin_port), 30041);
	assert_int_equal(ntohl(addr_in->sin_addr.s_addr), 0x7f000064);
	assert_int_equal(addr_len, sizeof(struct sockaddr_in));
}

static void test_parse_ipv6(void **)
{
	struct sockaddr_storage addr;
	socklen_t addr_len = sizeof(addr);
	scion_ia ia;

	assert_int_equal(
		scion_addr_parse("2-ff00:0:222,fd00:f00d:cafe::7f00:55", 1234, &ia, (struct sockaddr *)&addr, &addr_len), 0);

	struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr;
	struct in6_addr expected;
	assert_int_equal(inet_pton(AF_INET6, "fd00:f00d:cafe::7f00:55", &expected), 1);
	assert_int_equal(addr_in6->sin6_family, AF_INET6);
	assert_int_equal(ntohs(addr_in6->sin6_port), 1234);
	assert_memory_equal(&addr_in6->sin6_addr, &expected, sizeof(expected));
	assert_int_equal(addr_len, sizeof(struct sockaddr_in6));
}

static void test_parse_invalid(void **)
{
	const char *invalid[] = {
		"",
		"1-ff00:0:133",
		"1-ff00:0:133,",
		",127.0.0.1",
		"1-ff00:0:133,not-an-ip",
		"not-an-ia,127.0.0.1",
		"1-ff00:0:133,127.0.0.256",
	};

	for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
		struct sockaddr_storage addr;
		socklen_t addr_len = sizeof(addr);
		scion_ia ia;
		assert_int_equal(
			scion_addr_parse(invalid[i], 1, &ia, (struct sockaddr *)&addr, &addr_len), SCION_ERR_ADDR_INVALID);
	}
}

static void test_parse_address_buffer_too_small(void **)
{
	struct sockaddr_in addr;
	socklen_t addr_len = sizeof(addr);
	scion_ia ia;

	// An IPv6 address does not fit into a sockaddr_in
	assert_int_equal(scion_addr_parse("1-ff00:0:133,fd00::1", 1, &ia, (struct sockaddr *)&addr, &addr_len),
		SCION_ERR_ADDR_INVALID);
}

static void test_from_ip(void **)
{
	struct sockaddr_storage addr;
	socklen_t addr_len;

	assert_int_equal(scion_addr_from_ip(SCION_AF_INET, "10.1.2.3", 80, &addr, &addr_len), 0);
	struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
	assert_int_equal(addr_in->sin_family, AF_INET);
	assert_int_equal(ntohs(addr_in->sin_port), 80);
	assert_int_equal(ntohl(addr_in->sin_addr.s_addr), 0x0a010203);
	assert_int_equal(addr_len, sizeof(struct sockaddr_in));

	assert_int_equal(scion_addr_from_ip(SCION_AF_INET6, "fd00::2", 81, &addr, &addr_len), 0);
	struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr;
	struct in6_addr expected;
	assert_int_equal(inet_pton(AF_INET6, "fd00::2", &expected), 1);
	assert_int_equal(addr_in6->sin6_family, AF_INET6);
	assert_int_equal(ntohs(addr_in6->sin6_port), 81);
	assert_memory_equal(&addr_in6->sin6_addr, &expected, sizeof(expected));
	assert_int_equal(addr_len, sizeof(struct sockaddr_in6));
}

static void test_from_ip_wildcard(void **)
{
	struct sockaddr_storage addr;
	socklen_t addr_len;

	assert_int_equal(scion_addr_from_ip(SCION_AF_INET, NULL, 0, &addr, &addr_len), 0);
	assert_int_equal(((struct sockaddr_in *)&addr)->sin_addr.s_addr, htonl(INADDR_ANY));
	assert_int_equal(((struct sockaddr_in *)&addr)->sin_port, 0);

	assert_int_equal(scion_addr_from_ip(SCION_AF_INET6, NULL, 30041, &addr, &addr_len), 0);
	assert_true(IN6_IS_ADDR_UNSPECIFIED(&((struct sockaddr_in6 *)&addr)->sin6_addr));
	assert_int_equal(ntohs(((struct sockaddr_in6 *)&addr)->sin6_port), 30041);
}

static void test_from_ip_invalid(void **)
{
	struct sockaddr_storage addr;
	socklen_t addr_len;

	// The address does not belong to the family.
	assert_int_equal(scion_addr_from_ip(SCION_AF_INET, "fd00::2", 1, &addr, &addr_len), SCION_ERR_ADDR_INVALID);
	assert_int_equal(scion_addr_from_ip(SCION_AF_INET6, "10.1.2.3", 1, &addr, &addr_len), SCION_ERR_ADDR_INVALID);
	assert_int_equal(scion_addr_from_ip(SCION_AF_INET, "garbage", 1, &addr, &addr_len), SCION_ERR_ADDR_INVALID);
	assert_int_equal(scion_addr_from_ip((enum scion_addr_family)12345, "10.1.2.3", 1, &addr, &addr_len),
		SCION_ERR_ADDR_FAMILY_UNKNOWN);
}

int run_addr_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_parse_ipv4),
		cmocka_unit_test(test_parse_ipv6),
		cmocka_unit_test(test_parse_invalid),
		cmocka_unit_test(test_parse_address_buffer_too_small),
		cmocka_unit_test(test_from_ip),
		cmocka_unit_test(test_from_ip_wildcard),
		cmocka_unit_test(test_from_ip_invalid),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
