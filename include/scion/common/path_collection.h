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

#include "scion/data_plane/path.h"

typedef bool scion_path_selector(struct scion_path *path);

struct scion_path_collection {
	struct scion_linked_list *list;
};

int scion_path_collection_init(struct scion_path_collection **paths);

void scion_path_collection_free(struct scion_path_collection *paths);

struct scion_path *scion_path_collection_find(struct scion_path_collection *paths, scion_path_selector selector);

struct scion_path *scion_path_collection_pop(struct scion_path_collection *paths);

/*
 * FUNCTION: scion_path_collection_print
 * -------------------
 * Prints all the paths from a collection.
 * """
 * [0]:  Hops: [1ff0000000111 42>2 1ff0000000110 3>51 1ff0000000112] MTU: 1280
 * [1]:  Hops: [1ff0000000111 42>2 1ff0000000110 4>52 1ff0000000112] MTU: 1280
 * [2]:  Hops: [1ff0000000111 41>1 1ff0000000110 3>51 1ff0000000112] MTU: 1280
 * [3]:  Hops: [1ff0000000111 41>1 1ff0000000110 4>52 1ff0000000112] MTU: 1280
 * """
 *
 * Arguments:
 *      - struct scion_path_collection *paths: Pointer to a scion_path_collection which contains scion_path structs.
 */
void scion_path_collection_print(struct scion_path_collection *paths);
