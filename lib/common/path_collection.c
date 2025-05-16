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

#include <assert.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "common/path_collection.h"

static struct scion_path_collection *scion_path_collection_from_list(struct scion_linked_list *list)
{
	struct scion_path_collection *paths = malloc(sizeof(*paths));
	if (paths == NULL) {
		return NULL;
	}

	paths->list = list;
	return paths;
}

int scion_path_collection_init(struct scion_path_collection **paths)
{
	assert(paths);

	struct scion_linked_list *list = scion_list_create(SCION_LIST_CUSTOM_FREE(scion_path_free));
	struct scion_path_collection *new_paths = scion_path_collection_from_list(list);

	if (new_paths == NULL) {
		return SCION_MEM_ALLOC_FAIL;
	}

	*paths = new_paths;

	return 0;
}

void scion_path_collection_free(struct scion_path_collection *paths)
{
	if (paths == NULL) {
		return;
	}

	scion_list_free(paths->list);
	free(paths);
}

struct scion_path *scion_path_collection_find(
	struct scion_path_collection *paths, struct scion_path_predicate predicate)
{
	assert(paths);
	assert(paths->list);

	return scion_list_find(paths->list,
		(struct scion_list_predicate){ .fn = (scion_list_predicate_fn)predicate.fn, .ctx = predicate.ctx });
}

struct scion_path *scion_path_collection_pop(struct scion_path_collection *paths)
{
	assert(paths);
	assert(paths->list);

	return scion_list_pop(paths->list);
}

struct scion_path *scion_path_collection_first(struct scion_path_collection *paths)
{
	assert(paths);

	struct scion_linked_list_node *first = paths->list->first;

	if (first == NULL) {
		return NULL;
	}

	return first->value;
}

void scion_path_collection_sort(struct scion_path_collection *paths, struct scion_path_comparator comparator)
{
	assert(paths);

	return scion_list_sort(paths->list,
		(struct scion_list_comparator){
			.fn = (scion_list_comparator_fn)comparator.fn, .ctx = comparator.ctx, .ascending = comparator.ascending });
}

void scion_path_collection_filter(struct scion_path_collection *paths, struct scion_path_predicate predicate)
{
	assert(paths);

	return scion_list_filter(paths->list,
		(struct scion_list_predicate){ .fn = (scion_list_predicate_fn)predicate.fn, .ctx = predicate.ctx },
		SCION_LIST_CUSTOM_FREE(scion_path_free));
}

size_t scion_path_collection_size(struct scion_path_collection *paths)
{
	assert(paths);

	return paths->list->size;
}

void scion_path_collection_print(struct scion_path_collection *paths)
{
	struct scion_linked_list *list = paths->list;
	if (!paths || !list || list->size == 0) {
		return;
	}
	(void)printf("Available paths:\n");
	uint16_t i = 0;
	struct scion_linked_list_node *curr = list->first;
	size_t length = 0;
	while (curr) {
		struct scion_path *path = curr->value;

		if (path->path_type == SCION_PATH_TYPE_EMPTY) {
			if (i == 0) {
				(void)printf("0 Hops:\n");
			}
		} else {
			if (path->metadata->interfaces == NULL) {
				(void)printf(
					"[%" PRIu16
					"]: Path priniting unavailable due to missing metadata; Enable DEBUG MODE during path generation. "
					"(IMPORTANT: deserialized paths can never be printed as the metadata is never present)\n",
					i);
				continue;
			}

			if ((path->metadata->interfaces->size / 2 + 1) > length) {
				length = (path->metadata->interfaces->size / 2 + 1);
				(void)printf("%zu Hops:\n", length);
			}
		}

		(void)printf("[%" PRIu16 "]:  ", i);
		scion_path_print(path);

		i++;
		curr = curr->next;
	}
}
