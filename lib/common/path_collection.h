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

#include <stdbool.h>

#include "data_plane/path.h"
#include "scion/scion_scmp.h"
#include <scion/scion.h>
#include <scion/scion_path.h>

struct scion_path_collection {
	struct scion_list *list;
};

int scion_path_collection_init(struct scion_path_collection **paths);

/**
 * Marks the paths that an SCMP error affects as down. A path that is down keeps the time of its first mark.
 */
void scion_path_collection_mark_down(struct scion_path_collection *paths, const struct scion_scmp_error *error);

/**
 * Takes over the down marks of the old paths to the paths that are the same.
 * @return The new path that is the same as the old current path, or NULL if there is none.
 */
struct scion_path *scion_path_collection_carry_over(struct scion_path_collection *new_paths,
	struct scion_path_collection *old_paths, const struct scion_path *old_current);
