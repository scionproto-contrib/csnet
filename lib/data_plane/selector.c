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

#include "data_plane/selector.h"
#include "common/path_collection.h"
#include "data_plane/path.h"
#include "scion/scion_path.h"
#include "scion/scion_selector.h"
#include "util/list.h"

static struct scion_path *default_select(
	struct scion_path_collection *paths, const struct scion_path *current, void *ctx)
{
	(void)ctx;

	struct scion_path *first_up = NULL;
	struct scion_path *first_down = NULL;
	for (struct scion_list_node *node = paths->list->first; node != NULL; node = node->next) {
		struct scion_path *path = node->value;
		if (!scion_path_is_down(path)) {
			if (path == current) {
				return path;
			}
			if (first_up == NULL) {
				first_up = path;
			}
		} else if (first_down == NULL || path->down_since < first_down->down_since) {
			first_down = path;
		}
	}

	return first_up != NULL ? first_up : first_down;
}

struct scion_selector scion_selector_default = { .fn = default_select, .ctx = NULL };
