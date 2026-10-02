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
#include <string.h>

#include "data_plane/underlay.h"
#include "test_underlay.h"

static void test_underlay_probe_ipv4_loopback(void **)
{
	struct scion_underlay underlay = { .addr_family = SCION_AF_INET, .addrlen = sizeof(struct sockaddr_in) };
	struct sockaddr_in *remote = (struct sockaddr_in *)&underlay.addr;
	remote->sin_family = AF_INET;
	remote->sin_port = htons(30042);
	assert_int_equal(inet_pton(AF_INET, "127.0.0.1", &remote->sin_addr), 1);

	struct sockaddr_in local;
	socklen_t local_len = sizeof(local);
	assert_int_equal(scion_underlay_probe(&underlay, (struct sockaddr *)&local, &local_len), 0);

	// Connecting to a loopback address selects a loopback source address.
	assert_int_equal(local.sin_family, AF_INET);
	assert_uint_equal(ntohl(local.sin_addr.s_addr), INADDR_LOOPBACK);
}

static void test_underlay_probe_unknown_address_family(void **)
{
	struct scion_underlay underlay = { .addr_family = (enum scion_addr_family)12345 };

	struct sockaddr_in local;
	socklen_t local_len = sizeof(local);
	assert_int_equal(scion_underlay_probe(&underlay, (struct sockaddr *)&local, &local_len), SCION_ERR_GENERIC);
}

int run_underlay_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_underlay_probe_ipv4_loopback),
		cmocka_unit_test(test_underlay_probe_unknown_address_family),
	};

	return cmocka_run_group_tests(tests, NULL, NULL);
}
