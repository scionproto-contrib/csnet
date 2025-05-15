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

#include <stdint.h>
#include <stdlib.h>

#include "util/linked_list.h"

#include <assert.h>

static void scion_list_node_free(struct scion_linked_list_node *node, struct scion_list_value_free free_value)
{
	if (node == NULL) {
		return;
	}

	// Free node value of freeing function is provided
	if (free_value.fn != NULL) {
		free_value.fn(node->value, free_value.ctx);
	}

	node->value = NULL;
	node->next = NULL;
	free(node);
}

void scion_list_free(struct scion_linked_list *list)
{
	if (list == NULL) {
		return;
	}
	struct scion_linked_list_node *curr;
	struct scion_linked_list_node *next = list->first;
	while (next) {
		curr = next;
		next = curr->next;

		scion_list_node_free(curr, list->free_value);
	}
	list->size = 0;
	list->first = NULL;
	list->last = NULL;
	free(list);
}

struct scion_linked_list *scion_list_create(struct scion_list_value_free free_value)
{
	struct scion_linked_list *list = malloc(sizeof(*list));
	if (list == NULL) {
		return NULL;
	}
	list->size = 0;
	list->first = NULL;
	list->last = NULL;

	list->free_value = free_value;

	return list;
}

void scion_list_append(struct scion_linked_list *list, void *value)
{
	if (list == NULL) {
		return;
	}
	struct scion_linked_list_node *node = malloc(sizeof(*node));
	node->value = value;
	node->next = NULL;
	if (list->size == 0) {
		list->first = node;
		list->last = node;
	} else {
		list->last->next = node;
		list->last = node;
	}
	list->size++;
}

void scion_list_append_all(struct scion_linked_list *dst_list, struct scion_linked_list *src_list)
{
	if (dst_list == NULL || src_list == NULL) {
		return;
	}
	struct scion_linked_list_node *curr = src_list->first;
	while (curr) {
		scion_list_append(dst_list, curr->value);
		curr = curr->next;
	}
}

void *scion_list_pop(struct scion_linked_list *list)
{
	if (list == NULL) {
		return NULL;
	}
	if (list->size == 0) {
		return NULL;
	}

	struct scion_linked_list_node *first_node = list->first;
	void *value_ptr = first_node->value;

	if (!first_node->next) {
		list->first = NULL;
		list->last = NULL;
	} else {
		list->first = first_node->next;
	}
	list->size--;

	first_node->value = NULL;
	first_node->next = NULL;
	scion_list_node_free(first_node, SCION_LIST_NO_FREE_VALUES);

	return value_ptr;
}

void scion_list_reverse(struct scion_linked_list *list)
{
	if (list == NULL) {
		return;
	}
	if (list->size <= 1) {
		// Empty list or list with single element.
		return;
	}

	struct scion_linked_list_node *prev = list->first;
	struct scion_linked_list_node *curr = prev->next;
	struct scion_linked_list_node *next;

	while (curr) {
		next = curr->next;
		curr->next = prev;
		prev = curr;
		curr = next;
	}

	list->first->next = NULL;
	prev = list->first;
	list->first = list->last;
	list->last = prev;
}

/**
 * Updates a list with a new head and updates last pointer and size.
 */
static void update_list(struct scion_linked_list *list, struct scion_linked_list_node *new_head)
{
	struct scion_linked_list_node *current = new_head;
	struct scion_linked_list_node *prev = NULL;
	size_t count = 0;
	while (current != NULL) {
		count += 1;
		prev = current;
		current = current->next;
	}

	list->first = new_head;
	list->last = prev;
	list->size = count;
}

static struct scion_linked_list_node *merge(
	struct scion_linked_list_node *left, struct scion_linked_list_node *right, struct scion_list_comparator comparator)
{
	if (left == NULL)
		return right;
	if (right == NULL)
		return left;

	int compare_result = comparator.fn(left->value, right->value, comparator.ctx);

	// if left < right and ascending or left > right and descending
	if ((compare_result < 0 && comparator.ascending) || (compare_result > 0 && !comparator.ascending)) {
		left->next = merge(left->next, right, comparator);
		return left;
	} else {
		right->next = merge(left, right->next, comparator);
		return right;
	}
}

static struct scion_linked_list_node *merge_sort(
	struct scion_linked_list_node *head, struct scion_list_comparator comparator)
{
	if (head == NULL || head->next == NULL) {
		return head;
	}

	struct scion_linked_list_node *slow = head;
	struct scion_linked_list_node *fast = head->next;

	while (fast && fast->next) {
		slow = slow->next;
		fast = fast->next->next;
	}

	struct scion_linked_list_node *mid = slow->next;
	slow->next = NULL;

	struct scion_linked_list_node *left = merge_sort(head, comparator);
	struct scion_linked_list_node *right = merge_sort(mid, comparator);

	return merge(left, right, comparator);
}

void scion_list_sort(struct scion_linked_list *list, struct scion_list_comparator comparator)
{
	size_t old_size = list->size;
	struct scion_linked_list_node *new_head = merge_sort(list->first, comparator);

	update_list(list, new_head);
	assert(old_size == list->size);
}

static struct scion_linked_list_node *filter(
	struct scion_linked_list_node *head, struct scion_list_predicate predicate, struct scion_list_value_free free_value)
{
	if (head == NULL) {
		return NULL;
	}

	struct scion_linked_list_node *filtered_next = filter(head->next, predicate, free_value);

	if (predicate.fn(head->value, predicate.ctx)) {
		head->next = filtered_next;
		return head;
	} else {
		// filter out current head and free node (and possibly also the value)
		scion_list_node_free(head, free_value);
		return filtered_next;
	}
}

void scion_list_filter(
	struct scion_linked_list *list, struct scion_list_predicate predicate, struct scion_list_value_free free_value)
{
	struct scion_linked_list_node *new_head = filter(list->first, predicate, free_value);

	update_list(list, new_head);
}

void *scion_list_get(struct scion_linked_list *list, size_t n)
{
	if (list == NULL) {
		return NULL;
	}
	if (n > list->size - 1) {
		return NULL;
	}

	struct scion_linked_list_node *node = list->first;
	for (size_t i = 0; i < n; i++) {
		if (node == NULL) {
			// Handle corrupt list
			return NULL;
		}
		node = node->next;
	}
	return node->value;
}

void *scion_list_find(struct scion_linked_list *list, struct scion_list_predicate predicate)
{
	struct scion_linked_list_node *node = list->first;
	while (node != NULL) {
		if (predicate.fn(node->value, predicate.ctx)) {
			return node->value;
		}

		node = node->next;
	}

	return NULL;
}

size_t scion_list_size(struct scion_linked_list *list)
{
	assert(list);
	return list->size;
}

void scion_list_value_free_wrapper(void *value, void (*free_fn)(void *))
{
	if (free_fn == NULL) {
		return;
	}

	free_fn(value);
}
