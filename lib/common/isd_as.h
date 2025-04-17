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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <scion/scion.h>

#define SCION_IA_BYTES UINT16_C(8)
#define SCION_ISD_BITS UINT16_C(16)
#define SCION_AS_BITS UINT16_C(48)
#define SCION_MAX_ISD (uint16_t)((1 << SCION_ISD_BITS) - 1)
#define SCION_MAX_AS (uint64_t)(((uint64_t)1 << SCION_AS_BITS) - 1)

typedef uint16_t scion_isd;
typedef uint64_t scion_as;
typedef uint64_t scion_ia;

scion_ia scion_ia_from_isd_as(scion_isd isd, scion_as as);
scion_isd scion_ia_get_isd(scion_ia ia);
scion_as scion_ia_get_as(scion_ia ia);
scion_ia scion_ia_to_wildcard(scion_ia ia);
bool scion_ia_is_wildcard(scion_ia ia);
void scion_ia_print(scion_ia ia);
int scion_ia_parse(const char *str, size_t len, scion_ia *ia);
