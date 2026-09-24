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

#include <cmocka.h>
#include <string.h>

#include "test_isd_as.h"
#include "common/isd_as.h"

static void test_ia_from_isd_as(void **)
{
	scion_isd isd = 0x2;
	scion_as as = 0xff0000000222;
	scion_ia ia = scion_ia_from_isd_as(isd, as);
	assert_uint_equal(ia, 0x2ff0000000222);
}

static void test_ia_from_isd_as_too_large_as(void **)
{
	scion_isd isd = 0x2;
	scion_as as = 0x55ff0000000222;
	scion_ia ia = scion_ia_from_isd_as(isd, as);
	assert_uint_equal(ia, 0x2ff0000000222);
}

static void test_get_isd(void **)
{
	scion_ia ia = 0x2ff0000000222;
	scion_isd isd = scion_ia_get_isd(ia);
	assert_uint_equal(isd, 0x2);
}

static void test_get_as(void **)
{
	scion_ia ia = 0x2ff0000000222;
	scion_as as = scion_ia_get_as(ia);
	assert_uint_equal(as, 0xff0000000222);
}

static void test_to_wildcard(void **)
{
	scion_ia ia = 0x2ff0000000222;
	scion_ia wc = scion_ia_to_wildcard(ia);
	scion_as as = scion_ia_get_as(wc);
	assert_uint_equal(as, 0x0);
}

static void test_is_wildcard(void **)
{
	scion_ia ia = 0x2ff0000000222;
	assert_false(scion_ia_is_wildcard(ia));
	assert_true(scion_ia_is_wildcard(scion_ia_to_wildcard(ia)));

	ia = 0x2000000000000;
	assert_true(scion_ia_is_wildcard(ia));

	ia = 0x0ff0000000222;
	assert_true(scion_ia_is_wildcard(ia));

	ia = 0x0;
	assert_true(scion_ia_is_wildcard(ia));
}

static void test_parse_ia(void **)
{
	scion_ia ia;

	char buf[] = "2-ff00:0:222";
	assert_int_equal(scion_ia_parse(buf, strlen(buf), &ia), 0);
	assert_uint_equal(ia, 0x2ff0000000222);

	char buf2[] = "71-88";
	assert_int_equal(scion_ia_parse(buf2, strlen(buf2), &ia), 0);
	assert_uint_equal(ia, 0x47000000000058);

	char buf3[] = "64-196722";
	assert_int_equal(scion_ia_parse(buf3, strlen(buf3), &ia), 0);
	assert_uint_equal(ia, 0x40000000030072);
}

int run_isd_as_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_ia_from_isd_as),
		cmocka_unit_test(test_ia_from_isd_as_too_large_as),
		cmocka_unit_test(test_get_isd),
		cmocka_unit_test(test_get_as),
		cmocka_unit_test(test_to_wildcard),
		cmocka_unit_test(test_is_wildcard),
		cmocka_unit_test(test_parse_ia),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
