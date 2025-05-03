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

static void scion_list_node_free(struct scion_linked_list_node *node, scion_list_value_free free_value)
{
	if (node == NULL) {
		return;
	}

	// Free node value of freeing function is provided
	if (free_value != NULL) {
		free_value(node->value);
	}

	node->value = NULL;
	node->next = NULL;
	free(node);
}

void scion_list_free(struct scion_linked_list *list, scion_list_value_free free_value)
{
	if (list == NULL) {
		return;
	}
	struct scion_linked_list_node *curr;
	struct scion_linked_list_node *next = list->first;
	while (next) {
		curr = next;
		next = curr->next;

		scion_list_node_free(curr, free_value);
	}
	list->size = 0;
	list->first = NULL;
	list->last = NULL;
	free(list);
}

struct scion_linked_list *scion_list_create(void)
{
	struct scion_linked_list *list = malloc(sizeof(*list));
	if (list == NULL) {
		return NULL;
	}
	list->size = 0;
	list->first = NULL;
	list->last = NULL;
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
	scion_list_node_free(first_node, NULL);

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

static struct scion_linked_list_node *merge(struct scion_linked_list_node *left, struct scion_linked_list_node *right,
	scion_list_comparator compare, bool ascending)
{
	if (left == NULL)
		return right;
	if (right == NULL)
		return left;

	int compare_result = compare(left->value, right->value);

	// if left < right and ascending or left > right and descending
	if ((compare_result < 0 && ascending) || (compare_result > 0 && !ascending)) {
		left->next = merge(left->next, right, compare, ascending);
		return left;
	} else {
		right->next = merge(left, right->next, compare, ascending);
		return right;
	}
}

static struct scion_linked_list_node *merge_sort(
	struct scion_linked_list_node *head, scion_list_comparator compare, bool ascending)
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

	struct scion_linked_list_node *left = merge_sort(head, compare, ascending);
	struct scion_linked_list_node *right = merge_sort(mid, compare, ascending);

	return merge(left, right, compare, ascending);
}

void scion_list_sort(struct scion_linked_list *list, scion_list_comparator compare, bool ascending)
{
	size_t old_size = list->size;
	struct scion_linked_list_node *new_head = merge_sort(list->first, compare, ascending);

	update_list(list, new_head);
	assert(old_size == list->size);
}

static struct scion_linked_list_node *filter(
	struct scion_linked_list_node *head, scion_list_predicate predicate, scion_list_value_free free_value)
{
	if (head == NULL) {
		return NULL;
	}

	struct scion_linked_list_node *filtered_next = filter(head->next, predicate, free_value);

	if (predicate(head->value)) {
		head->next = filtered_next;
		return head;
	} else {
		// filter out current head and free node (and possibly also the value)
		scion_list_node_free(head, free_value);
		return filtered_next;
	}
}

void scion_list_filter(struct scion_linked_list *list, scion_list_predicate predicate, scion_list_value_free free_value)
{
	struct scion_linked_list_node *new_head = filter(list->first, predicate, free_value);

	update_list(list, new_head);
}

void *scion_list_get(struct scion_linked_list *list, uint32_t n)
{
	if (list == NULL) {
		return NULL;
	}
	if (n > list->size - 1) {
		return NULL;
	}

	struct scion_linked_list_node *node = list->first;
	for (uint32_t i = 0; i < n; i++) {
		if (node == NULL) {
			// Handle corrupt list
			return NULL;
		}
		node = node->next;
	}
	return node->value;
}
