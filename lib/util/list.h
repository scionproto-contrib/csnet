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

/**
 * @file list.h
 *
 * The list util of CSNET.
 */

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define SCION_LIST_CUSTOM_FREE(free_fn) \
	((struct scion_list_value_free){ .fn = (scion_list_value_free_fn)scion_list_value_free_wrapper, .ctx = (free_fn) })
#define SCION_LIST_CUSTOM_FREE_WITH_CTX(free_fn, ctx_arg) \
	((struct scion_list_value_free){ .fn = (scion_list_value_free_fn)(free_fn), .ctx = (ctx_arg) })

#define SCION_LIST_NO_FREE_VALUES SCION_LIST_CUSTOM_FREE(NULL)
#define SCION_LIST_SIMPLE_FREE SCION_LIST_CUSTOM_FREE(free)

struct scion_list_node {
	void *value;
	struct scion_list_node *next;
};

typedef void (*scion_list_value_free_fn)(void *value, void *ctx);

struct scion_list_value_free {
	scion_list_value_free_fn fn;
	void *ctx;
};

struct scion_list {
	size_t size;
	struct scion_list_node *first;
	struct scion_list_node *last;

	struct scion_list_value_free free_value;
};

void scion_list_value_free_wrapper(void *value, void (*free_fn)(void *));

typedef bool (*scion_list_predicate_fn)(void *value, void *ctx);

struct scion_list_predicate {
	scion_list_predicate_fn fn;
	void *ctx;
};

typedef int (*scion_list_comparator_fn)(void *value_one, void *value_two, void *ctx);

struct scion_list_comparator {
	scion_list_comparator_fn fn;
	void *ctx;

	bool ascending;
};

/**
 * Frees a list.
 * @param[in] list The list to free.
 */
void scion_list_free(struct scion_list *list);

/**
 * Creates a list.
 * @param free_value The value freer to use.
 * The following macros are available:
 * - SCION_LIST_NO_FREE_VALUES: a value freer that does not free the values
 * - SCION_LIST_SIMPLE_FREE: a value freer that uses the c lib free function to free the values
 * - SCION_LIST_CUSTOM_FREE(free_fn): a value freer that uses the custom free_fn to free the values
 * - SCION_LIST_CUSTOM_FREE_WITH_CTX(free_fn, ctx): a value freer that uses the custom free_fn and context ctx to free
 * the values
 * @return The newly created list.
 */
struct scion_list *scion_list_create(struct scion_list_value_free free_value);

void scion_list_append(struct scion_list *list, void *value);

void scion_list_append_all(struct scion_list *dst_list, struct scion_list *src_list);

void *scion_list_pop(struct scion_list *list);

void scion_list_reverse(struct scion_list *list);

void scion_list_sort(struct scion_list *list, struct scion_list_comparator compare);

void scion_list_filter(struct scion_list *list, struct scion_list_predicate predicate);

void *scion_list_get(struct scion_list *list, size_t n);

void *scion_list_find(struct scion_list *list, struct scion_list_predicate predicate);

size_t scion_list_size(struct scion_list *list);
