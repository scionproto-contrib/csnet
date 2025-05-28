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

#include "test_isd_as.h"
#include "common/isd_as.h"

#include <string.h>

int scion_test_ia_from_isd_as(void)
{
	int ret = 0;
	scion_isd isd = 0x2;
	scion_as as = 0xff0000000222;
	scion_ia ia = scion_ia_from_isd_as(isd, as);
	if (ia != 0x2ff0000000222) {
		ret = 1;
	}
	return ret;
}

int scion_test_ia_from_isd_as_too_large_as(void)
{
	int ret = 0;
	scion_isd isd = 0x2;
	scion_as as = 0x55ff0000000222;
	scion_ia ia = scion_ia_from_isd_as(isd, as);
	if (ia != 0x2ff0000000222) {
		ret = 1;
	}
	return ret;
}

int scion_test_get_isd(void)
{
	int ret = 0;
	scion_ia ia = 0x2ff0000000222;
	scion_isd isd = scion_ia_get_isd(ia);
	if (isd != 0x2) {
		ret = 1;
	}
	return ret;
}

int scion_test_get_as(void)
{
	int ret = 0;
	scion_ia ia = 0x2ff0000000222;
	scion_as as = scion_ia_get_as(ia);
	if (as != 0xff0000000222) {
		ret = 1;
	}
	return ret;
}

int scion_test_to_wildcard(void)
{
	int ret = 0;
	scion_ia ia = 0x2ff0000000222;
	scion_ia wc = scion_ia_to_wildcard(ia);
	scion_as as = scion_ia_get_as(wc);
	if (as != 0x0) {
		ret = 1;
	}
	return ret;
}

int scion_test_is_wildcard(void)
{
	int ret = 0;
	scion_ia ia = 0x2ff0000000222;
	if (scion_ia_is_wildcard(ia)) {
		ret = 1;
	}
	if (!scion_ia_is_wildcard(scion_ia_to_wildcard(ia))) {
		ret = 1;
	}
	ia = 0x2000000000000;
	if (!scion_ia_is_wildcard(ia)) {
		ret = 1;
	}
	ia = 0x0ff0000000222;
	if (!scion_ia_is_wildcard(ia)) {
		ret = 1;
	}
	ia = 0x0;
	if (!scion_ia_is_wildcard(ia)) {
		ret = 1;
	}

	return ret;
}

int scion_test_parse_ia(void)
{
	int ret = 0;
	scion_ia ia;

	char buf[] = "2-ff00:0:222";
	ret = scion_ia_parse(buf, strlen(buf), &ia);
	if (ret != 0) {
		return ret;
	}
	if (ia != 0x2ff0000000222) {
		return 1;
	}

	char buf2[] = "71-88";
	ret = scion_ia_parse(buf2, strlen(buf2), &ia);
	if (ret != 0) {
		return ret;
	}
	if (ia != 0x47000000000058) {
		return 2;
	}

	char buf3[] = "64-196722";
	ret = scion_ia_parse(buf3, strlen(buf3), &ia);
	if (ret != 0) {
		return ret;
	}
	if (ia != 0x40000000030072) {
		return 3;
	}

	return 0;
}
