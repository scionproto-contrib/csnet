// Copyright 2025 ETH Zurich
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

#pragma once

#include <stdint.h>
#include <string.h>

#if defined(__APPLE__)
#include <libkern/OSByteOrder.h>
#define htobe16(x) OSSwapHostToBigInt16(x)
#define be16toh(x) OSSwapBigToHostInt16(x)
#define htobe32(x) OSSwapHostToBigInt32(x)
#define be32toh(x) OSSwapBigToHostInt32(x)
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#else
#include <endian.h>
#endif

// Wire data is not necessarily aligned, so multi-byte fields must not be accessed by casting a buffer pointer.
static inline uint16_t scion_load_be16(const uint8_t *buf)
{
	uint16_t value;
	(void)memcpy(&value, buf, sizeof(value));
	return be16toh(value);
}

static inline uint32_t scion_load_be32(const uint8_t *buf)
{
	uint32_t value;
	(void)memcpy(&value, buf, sizeof(value));
	return be32toh(value);
}

static inline uint64_t scion_load_be64(const uint8_t *buf)
{
	uint64_t value;
	(void)memcpy(&value, buf, sizeof(value));
	return be64toh(value);
}

static inline void scion_store_be16(uint8_t *buf, uint16_t value)
{
	uint16_t be_value = htobe16(value);
	(void)memcpy(buf, &be_value, sizeof(be_value));
}

static inline void scion_store_be32(uint8_t *buf, uint32_t value)
{
	uint32_t be_value = htobe32(value);
	(void)memcpy(buf, &be_value, sizeof(be_value));
}

static inline void scion_store_be64(uint8_t *buf, uint64_t value)
{
	uint64_t be_value = htobe64(value);
	(void)memcpy(buf, &be_value, sizeof(be_value));
}
