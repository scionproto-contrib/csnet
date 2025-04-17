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

#include <stdint.h>

struct scion_linked_list_node {
	void *value;
	struct scion_linked_list_node *next;
};

struct scion_linked_list {
	uint32_t size;
	struct scion_linked_list_node *first;
	struct scion_linked_list_node *last;
};

typedef void (*scion_list_value_free)(void *value);

/**
 * Frees a linked list.
 * @param[in] list The linked list.
 * @param[in] free_value The freeing function used to free the values of the nodes. If NULL, the values of the nodes are
 * not freed.
 */
void scion_list_free(struct scion_linked_list *list, scion_list_value_free free_value);

/*
 * FUNCTION: scion_list_create
 * -----------------
 * Creates and initializes an empty scion_linked_list.
 *
 * Returns:
 *      - struct scion_linked_list *list: Pointer to a scion_linked_list struct.
 */
struct scion_linked_list *scion_list_create(void);

/*
 * FUNCTION: scion_list_append
 * -----------------
 * Adds a value to the end of a scion_linked_list.
 *
 * Arguments:
 *      - struct scion_linked_list *list: Pointer to a scion_linked_list struct.
 *      - void *ptr: Pointer to which will be added to the list.
 */
void scion_list_append(struct scion_linked_list *list, void *value);

/*
 * FUNCTION: scion_list_append_all
 * -----------------
 * Adds all elements (individually) from the source list to the end of the destination list.
 *
 * Arguments:
 *      - struct scion_linked_list *dst_list: Pointer to the destination scion_linked_list.
 *      - struct scion_linked_list *src_list: Pointer to the source scion_linked_list.
 */
void scion_list_append_all(struct scion_linked_list *dst_list, struct scion_linked_list *src_list);

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
void *scion_list_pop(struct scion_linked_list *list);

/*
 * FUNCTION: scion_list_reverse
 * -----------------
 * Reverses a linked list (in place).
 *
 * Arguments:
 *      - struct scion_linked_list *list: Pointer to a scion_linked_list struct which you want to reverse.
 */
void scion_list_reverse(struct scion_linked_list *list);

void *scion_list_get(struct scion_linked_list *list, uint32_t n);
