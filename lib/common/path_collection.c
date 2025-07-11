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

int scion_path_collection_init(struct scion_path_collection **paths)
{
	assert(paths);

	struct scion_list *list = scion_list_create(SCION_LIST_CUSTOM_FREE(scion_path_free));
	struct scion_path_collection *new_paths = malloc(sizeof(*new_paths));
	if (new_paths == NULL) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}

	new_paths->list = list;

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

	struct scion_list_node *first = paths->list->first;

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
		(struct scion_list_predicate){ .fn = (scion_list_predicate_fn)predicate.fn, .ctx = predicate.ctx });
}

size_t scion_path_collection_size(struct scion_path_collection *paths)
{
	assert(paths);

	return paths->list->size;
}

struct scion_path **scion_path_collection_as_array(struct scion_path_collection *paths, size_t *len)
{
	assert(paths);
	assert(len);

	struct scion_path **path_array = calloc(paths->list->size, sizeof(*path_array));
	struct scion_list_node *current = paths->list->first;

	size_t i = 0;
	while (current) {
		path_array[i++] = current->value;

		current = current->next;
	}

	*len = i;

	return path_array;
}

void scion_path_collection_print(struct scion_path_collection *paths)
{
	struct scion_list *list = paths->list;
	if (!paths || !list || list->size == 0) {
		return;
	}
	(void)printf("Available paths:\n");
	uint16_t i = 0;
	struct scion_list_node *curr = list->first;
	size_t length = 0;
	while (curr) {
		struct scion_path *path = curr->value;

		if (path->path_type == SCION_PATH_TYPE_EMPTY) {
			if (i == 0) {
				(void)printf("0 Hops:\n");
			}
		} else {
			if (path->metadata->interfaces == NULL) {
				(void)printf("[%" PRIu16 "]: Path priniting unavailable due to missing metadata."
							 "(IMPORTANT: deserialized paths can never be printed as the metadata is never present)\n",
					i);
				continue;
			}

			size_t current_length = scion_path_get_numhops(path);

			if (current_length > length) {
				length = current_length;
				(void)printf("%zu Hops:\n", length);
			}
		}

		(void)printf("[%" PRIu16 "]:  ", i);
		scion_path_print(path);

		i++;
		curr = curr->next;
	}
}
