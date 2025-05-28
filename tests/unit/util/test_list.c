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

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "test_list.h"
#include "util/list.h"

#include <unistd.h>

int scion_test_example(void)
{
	return 0;
}

int scion_test_list_create(void)
{
	int ret = 0;
	struct scion_list *list = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	if (list == NULL) {
		return 1;
	}

	if (list->size != 0) {
		ret = 1;
	}

	if (list->first != NULL || list->last != NULL) {
		ret = 1;
	}

	free(list);
	return ret;
}

int scion_test_list_append(void)
{
	struct scion_list *list = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	int a = 1001;

	scion_list_append(list, &a);

	if (list->size != 1) {
		goto cleanup_list;
	}
	if (list->first == NULL || list->last == NULL) {
		goto cleanup_list;
	}
	if (list->first != list->last) {
		goto cleanup_list;
	}
	struct scion_list_node *n = list->first;
	if (n->value == NULL) {
		goto cleanup_list;
	}
	if (n->next != NULL) {
		goto cleanup_list;
	}
	int b = *((int *)n->value);
	if (a != b) {
		goto cleanup_list;
	}

	b = 1002;
	scion_list_append(list, &b);
	scion_list_append(list, NULL);

	if (list->size != 3) {
		goto cleanup_list;
	}
	n = list->first;
	if (n == NULL) {
		goto cleanup_list;
	}
	int c = *((int *)n->value);
	if (a != c) {
		goto cleanup_list;
	}
	n = n->next;
	if (n == NULL) {
		goto cleanup_list;
	}
	c = *((int *)n->value);
	if (b != c) {
		goto cleanup_list;
	}
	n = n->next;
	if (n == NULL) {
		goto cleanup_list;
	}
	if (n->value != NULL) {
		goto cleanup_list;
	}
	if (n->next != NULL) {
		goto cleanup_list;
	}
	if (list->last != n) {
		goto cleanup_list;
	}

	scion_list_free(list);
	return 0;

cleanup_list:
	scion_list_free(list);
	return 1;
}

int scion_test_list_append_all_null(void)
{
	int ret = 0;
	struct scion_list *list = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	int a = 1;
	int b = 2;

	scion_list_append(list, &a);
	scion_list_append(list, &b);

	scion_list_append_all(list, NULL);

	if (list->size != 2) {
		ret = 1;
	}

	scion_list_free(list);
	return ret;
}

int scion_test_list_append_all(void)
{
	int ret = 0;

	struct scion_list *list_1 = scion_list_create(SCION_LIST_NO_FREE_VALUES);
	struct scion_list *list_2 = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	int a = 1;
	int b = 2;

	scion_list_append(list_1, &a);
	scion_list_append(list_1, &b);

	int c = 3;
	int d = 4;

	scion_list_append(list_2, &c);
	scion_list_append(list_2, &d);

	scion_list_append_all(list_1, list_2);

	if (list_1->size != 4) {
		scion_list_free(list_1);
		scion_list_free(list_2);
		return 1;
	}

	struct scion_list_node *curr = list_1->first;

	if (*((int *)curr->value) != 1) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 2) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 3) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 4) {
		ret = 1;
	}

	if (list_2->size != 2) {
		scion_list_free(list_1);
		scion_list_free(list_2);
		return 1;
	}

	curr = list_2->first;

	if (*((int *)curr->value) != 3) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 4) {
		ret = 1;
	}

	scion_list_free(list_1);
	scion_list_free(list_2);
	return ret;
}

int scion_test_list_pop(void)
{
	int ret = 0;

	if (scion_list_pop(NULL) != NULL) {
		ret = 1;
	}

	struct scion_list *list = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	if (scion_list_pop(list) != NULL) {
		ret = 1;
	}

	int a = 1;
	int b = 2;
	scion_list_append(list, &a);
	scion_list_append(list, &b);

	if (*((int *)scion_list_pop(list)) != 1) {
		ret = 1;
	}
	if (list->size != 1) {
		ret = 1;
	}

	if (*((int *)scion_list_pop(list)) != 2) {
		ret = 1;
	}
	if (list->size != 0) {
		ret = 1;
	}

	if (scion_list_pop(list) != NULL) {
		ret = 1;
	}
	if (list->size != 0) {
		ret = 1;
	}

	scion_list_free(list);
	return ret;
}

int scion_test_list_reverse(void)
{
	int ret = 0;

	struct scion_list *list = scion_list_create(SCION_LIST_NO_FREE_VALUES);
	struct scion_list_node *curr;

	scion_list_reverse(list);
	if (list->size != 0) {
		scion_list_free(list);
		return 1;
	}

	int a = 1;
	int b = 2;
	int c = 3;
	int d = 4;

	// 1 element
	scion_list_append(list, &a);
	scion_list_reverse(list);
	if (list->size != 1) {
		scion_list_free(list);
		return 1;
	}
	if (*((int *)list->first->value) != 1) {
		ret = 1;
	}

	// 2 elements
	scion_list_append(list, &b);
	scion_list_reverse(list);
	if (list->size != 2) {
		scion_list_free(list);
		return 1;
	}
	curr = list->first;
	if (*((int *)curr->value) != 2) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 1) {
		ret = 1;
	}

	scion_list_reverse(list);
	if (list->size != 2) {
		scion_list_free(list);
		return 1;
	}
	curr = list->first;
	if (*((int *)curr->value) != 1) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 2) {
		ret = 1;
	}

	// 3 elements
	scion_list_append(list, &c);
	scion_list_reverse(list);
	if (list->size != 3) {
		scion_list_free(list);
		return 1;
	}
	curr = list->first;
	if (*((int *)curr->value) != 3) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 2) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 1) {
		ret = 1;
	}

	scion_list_reverse(list);
	if (list->size != 3) {
		scion_list_free(list);
		return 1;
	}
	curr = list->first;
	if (*((int *)curr->value) != 1) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 2) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 3) {
		ret = 1;
	}

	// 4 elements
	scion_list_append(list, &d);
	scion_list_reverse(list);
	if (list->size != 4) {
		scion_list_free(list);
		return 1;
	}
	curr = list->first;
	if (*((int *)curr->value) != 4) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 3) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 2) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 1) {
		ret = 1;
	}

	scion_list_reverse(list);
	if (list->size != 4) {
		scion_list_free(list);
		return 1;
	}
	curr = list->first;
	if (*((int *)curr->value) != 1) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 2) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 3) {
		ret = 1;
	}
	curr = curr->next;
	if (*((int *)curr->value) != 4) {
		ret = 1;
	}

	scion_list_free(list);
	return ret;
}

// Warning: This test produces false positives with (negligible) probability of 1 / 2^64.
int scion_test_list_free(void)
{
	int ret = 0;
	struct scion_list *list = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	uint64_t random_val = ((uint64_t)rand() << 32) | ((uint64_t)rand());
	uint64_t *heap_memory = malloc(sizeof(*heap_memory));
	*heap_memory = random_val;
	scion_list_append(list, heap_memory);

	scion_list_free(list);

	// Check that heap_memory is not freed
	pid_t pid = fork();

	if (pid < 0) {
		ret = 1;
		goto exit;
	}

	if (pid == 0) {
		// Try dereference in child process
		if (*heap_memory == random_val) {
			exit(EXIT_SUCCESS);
		}

		exit(EXIT_FAILURE);
	} else {
		int status;
		// Wait for child process to exit
		waitpid(pid, &status, 0);

		if (status != EXIT_SUCCESS) {
			ret = 1;
			goto exit;
		}
	}

	free(heap_memory);

exit:
	return ret;
}

int scion_test_list_free_value(void)
{
	int ret = 0;
	struct scion_list *list = scion_list_create(SCION_LIST_SIMPLE_FREE);

	uint64_t random_val = ((uint64_t)rand() << 32) | ((uint64_t)rand());
	uint64_t *heap_memory = malloc(sizeof(*heap_memory));
	*heap_memory = random_val;
	scion_list_append(list, heap_memory);

	scion_list_free(list);

	// Check that heap_memory is freed
	pid_t pid = fork();

	if (pid < 0) {
		ret = 1;
		goto exit;
	}

	if (pid == 0) {
		// Try dereference in child process
		if (*heap_memory == random_val) {
			exit(EXIT_SUCCESS);
		}

		exit(EXIT_FAILURE);
	} else {
		int status;
		// Wait for child process to exit
		waitpid(pid, &status, 0);

		if (status == EXIT_SUCCESS) {
			ret = 1;
			goto exit;
		}
	}

exit:
	return ret;
}

struct custom_struct {
	uint64_t *data_buf;
};

static void custom_free(struct custom_struct *custom)
{
	if (custom == NULL) {
		return;
	}

	free(custom->data_buf);
	free(custom);
}

int scion_test_list_free_value_custom(void)
{
	int ret = 0;
	struct scion_list *list = scion_list_create(SCION_LIST_CUSTOM_FREE(custom_free));

	uint64_t random_val = ((uint64_t)rand() << 32) | ((uint64_t)rand());
	uint64_t *heap_memory = malloc(sizeof(*heap_memory));
	*heap_memory = random_val;
	struct custom_struct *custom = malloc(sizeof(*custom));
	custom->data_buf = heap_memory;

	scion_list_append(list, custom);

	scion_list_free(list);

	// Check that heap_memory is freed with custom freeing function
	pid_t pid = fork();

	if (pid < 0) {
		ret = 1;
		goto exit;
	}

	if (pid == 0) {
		// Try dereference in child process
		if (*heap_memory == random_val) {
			exit(EXIT_SUCCESS);
		}

		if (*custom->data_buf == random_val) {
			exit(EXIT_SUCCESS);
		}

		exit(EXIT_FAILURE);
	} else {
		int status;
		// Wait for child process to exit
		waitpid(pid, &status, 0);

		if (status == EXIT_SUCCESS) {
			ret = 1;
			goto exit;
		}
	}

exit:
	return ret;
}
