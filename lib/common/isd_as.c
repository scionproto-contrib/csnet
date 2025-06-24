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

#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/isd_as.h"

static_assert(sizeof("65535-ffff:ffff:ffff") <= SCION_IA_STRLEN, "SCION_IA_STRLEN is not large enough");

#define SCION_AS_MASK 0xffffffffffff

scion_ia scion_ia_from_isd_as(scion_isd isd, scion_as as)
{
	return (((scion_ia)isd) << SCION_AS_BITS) | ((scion_ia)as & SCION_AS_MASK);
}

scion_isd scion_ia_get_isd(scion_ia ia)
{
	return (scion_isd)(ia >> SCION_AS_BITS);
}

scion_as scion_ia_get_as(scion_ia ia)
{
	return (scion_as)(ia & SCION_MAX_AS);
}

scion_ia scion_ia_to_wildcard(scion_ia ia)
{
	return scion_ia_from_isd_as(scion_ia_get_isd(ia), 0);
}

bool scion_ia_is_wildcard(scion_ia ia)
{
	return scion_ia_get_isd(ia) == 0 || scion_ia_get_as(ia) == 0;
}

int scion_ia_str(scion_ia ia, char *buf, size_t buflen)
{
	char ia_str[SCION_IA_STRLEN];

	scion_isd isd = scion_ia_get_isd(ia);
	scion_as as = scion_ia_get_as(ia);

	uint16_t first = (uint16_t)((as >> 32) & 0xffff);
	uint16_t second = (uint16_t)((as >> 16) & 0xffff);
	uint16_t third = (uint16_t)(as & 0xffff);

	int print_ret = 0;
	if (first == 0) {
		uint32_t bgp_as = (uint32_t)as;
		print_ret = snprintf(ia_str, sizeof(ia_str), "%" PRIu16 "-%" PRIu32, isd, bgp_as);
	} else {
		print_ret = snprintf(
			ia_str, sizeof(ia_str), "%" PRIu16 "-%" PRIx16 ":%" PRIx16 ":%" PRIx16, isd, first, second, third);
	}

	if (print_ret < 0) {
		return SCION_GENERIC_ERR;
	}

	size_t strlen = (size_t)print_ret + 1;

	assert(strlen <= SCION_IA_STRLEN);

	if (buflen < strlen) {
		return SCION_BUFFER_SIZE_ERR;
	}

	(void)memcpy(buf, ia_str, strlen);
	return 0;
}

void scion_ia_print(scion_ia ia)
{
	char ia_str[SCION_IA_STRLEN];
	(void)scion_ia_str(ia, ia_str, sizeof(ia_str));
	(void)printf("%s", ia_str);
}

static int parse_isd(const char *buf, size_t len, scion_isd *isd)
{
	assert(strnlen(buf, len + 1) == len);

	char *end_ptr = NULL;
	long int num = strtol(buf, &end_ptr, 10);
	if (end_ptr == buf || *end_ptr != '\0' || ((num == LONG_MIN || num == LONG_MAX) && errno == ERANGE) || num < 0
		|| num > UINT16_MAX) {
		return SCION_ERR_INVALID_ISD_AS_STR;
	}

	*isd = (uint16_t)num;
	return 0;
}

static int parse_as(const char *buf, size_t len, scion_as *as)
{
	assert(strnlen(buf, len + 1) == len);

	char *end_ptr = NULL;
	char *colon_ptr = memchr(buf, 0x3a, len); // 0x3a == ':'
	if (colon_ptr != NULL) {
		long int num = strtol(buf, &end_ptr, 16);
		if (end_ptr == buf || ((num == LONG_MIN || num == LONG_MAX) && errno == ERANGE) || num < 0
			|| num > UINT16_MAX) {
			return SCION_ERR_INVALID_ISD_AS_STR;
		}
		*as = (scion_as)num << 32;

		num = strtol(end_ptr + 1, &end_ptr, 16); // TODO: Think about out-of-bounds access
		if (end_ptr == buf || ((num == LONG_MIN || num == LONG_MAX) && errno == ERANGE) || num < 0
			|| num > UINT16_MAX) {
			return SCION_ERR_INVALID_ISD_AS_STR;
		}
		*as |= (scion_as)num << 16;

		num = strtol(end_ptr + 1, &end_ptr, 16); // TODO: Think about out-of-bounds access
		if (end_ptr == buf || ((num == LONG_MIN || num == LONG_MAX) && errno == ERANGE) || num < 0
			|| num > UINT16_MAX) {
			return SCION_ERR_INVALID_ISD_AS_STR;
		}
		*as |= (scion_as)num;
	} else {
		// BGP-AS number, which is in decimal format.
		long int num = strtol(buf, &end_ptr, 10);
		if (end_ptr == buf || ((num == LONG_MIN || num == LONG_MAX) && errno == ERANGE) || num < 0) {
			return SCION_ERR_INVALID_ISD_AS_STR;
		}

		*as = (uint64_t)num;
	}
	return 0;
}

int scion_ia_parse(const char *str, size_t len, scion_ia *ia)
{
	int ret;

	char *dash_ptr = memchr(str, 0x2d, len); // 0x2d == '-'
	if (dash_ptr == NULL) {
		return SCION_ERR_INVALID_ISD_AS_STR;
	}

	ptrdiff_t offset = dash_ptr - str;
	if (offset <= 0 || (size_t)offset >= len) {
		return SCION_ERR_INVALID_ISD_AS_STR;
	}

	size_t isd_len = (size_t)(offset);
	size_t as_len = (size_t)(len - isd_len - 1);

	scion_isd isd;
	scion_as as;

	char isd_str[isd_len + 1];
	(void)memcpy(isd_str, str, isd_len);
	isd_str[isd_len] = 0x00;

	ret = parse_isd(isd_str, isd_len, &isd);
	if (ret != 0) {
		return ret;
	}

	char as_str[as_len + 1];
	(void)memcpy(as_str, dash_ptr + 1, as_len);
	as_str[as_len] = 0x00;

	ret = parse_as(as_str, as_len, &as);
	if (ret != 0) {
		return ret;
	}

	*ia = scion_ia_from_isd_as(isd, as);

	return 0;
}
