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
 * @file linked_list.h
 *
 * The linked list util of CSNET.
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

// TODO adjust my documentation
/**
 * Frees a linked list.
 * @param[in] list The linked list.
 * @param[in] free_value The value freer to use. The following macros are available:
 * - SCION_LIST_NO_FREE_VALUES: a value freer that does not free the value
 * - SCION_LIST_SIMPLE_FREE: a value freer that uses the c lib free function to free the value
 * - SCION_LIST_CUSTOM_FREE(free_fn): a value freer that uses the custom free_fn to free the value
 * - SCION_LIST_CUSTOM_FREE_WITH_CTX(free_fn, ctx): a value freer that uses the custom free_fn and context ctx to free
 * the value
 */
void scion_list_free(struct scion_list *list);

// TODO document me
struct scion_list *scion_list_create(struct scion_list_value_free free_value);

/*
 * FUNCTION: scion_list_append
 * -----------------
 * Adds a value to the end of a scion_linked_list.
 *
 * Arguments:
 *      - struct scion_linked_list *list: Pointer to a scion_linked_list struct.
 *      - void *ptr: Pointer to which will be added to the list.
 */
void scion_list_append(struct scion_list *list, void *value);

/*
 * FUNCTION: scion_list_append_all
 * -----------------
 * Adds all elements (individually) from the source list to the end of the destination list.
 *
 * Arguments:
 *      - struct scion_linked_list *dst_list: Pointer to the destination scion_linked_list.
 *      - struct scion_linked_list *src_list: Pointer to the source scion_linked_list.
 */
void scion_list_append_all(struct scion_list *dst_list, struct scion_list *src_list);

/*
 * FUNCTION: scion_list_pop
 * -----------------
 * Removes the first element from a scion_linked_list and returns the value pointer of this element.
 *
 * Arguments:
 *      - struct scion_linked_list *list: Pointer to a scion_linked_list struct.
 *
 * Returns:
 *      - void *value: value pointer of the former first element.
 */
void *scion_list_pop(struct scion_list *list);

/*
 * FUNCTION: scion_list_reverse
 * -----------------
 * Reverses a linked list (in place).
 *
 * Arguments:
 *      - struct scion_linked_list *list: Pointer to a scion_linked_list struct which you want to reverse.
 */
void scion_list_reverse(struct scion_list *list);

void scion_list_sort(struct scion_list *list, struct scion_list_comparator compare);

void scion_list_filter(
	struct scion_list *list, struct scion_list_predicate predicate, struct scion_list_value_free free_value);

void *scion_list_get(struct scion_list *list, size_t n);

void *scion_list_find(struct scion_list *list, struct scion_list_predicate predicate);

size_t scion_list_size(struct scion_list *list);
