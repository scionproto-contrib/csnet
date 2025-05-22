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

#include <math.h>
#include <stdint.h>

#include "common/isd_as.h"
#include "scion/scion.h"
#include "util/list.h"

void scion_geo_coordinates_free(struct scion_geo_coordinates *geo);

void scion_path_metadata_free(struct scion_path_metadata *path_meta);

struct scion_path_metadata *scion_path_metadata_collect(
	struct scion_list *interfaces, struct scion_list *as_entries, uint32_t mtu, int64_t expiry);

void scion_path_metadata_print(struct scion_path_metadata *path_meta);
