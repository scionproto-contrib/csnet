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

#include <cmocka.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

#include "test_list.h"
#include "util/list.h"

static void test_list_create(void **)
{
	struct scion_list *list = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	assert_non_null(list);
	assert_uint_equal(list->size, 0);
	assert_null(list->first);
	assert_null(list->last);

	free(list);
}

static void test_list_append(void **)
{
	struct scion_list *list = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	int a = 1001;
	scion_list_append(list, &a);

	assert_uint_equal(list->size, 1);
	assert_non_null(list->first);
	assert_ptr_equal(list->first, list->last);
	struct scion_list_node *n = list->first;
	assert_non_null(n->value);
	assert_null(n->next);
	assert_int_equal(*((int *)n->value), a);

	int b = 1002;
	scion_list_append(list, &b);
	scion_list_append(list, NULL);

	assert_uint_equal(list->size, 3);
	n = list->first;
	assert_non_null(n);
	assert_int_equal(*((int *)n->value), a);
	n = n->next;
	assert_non_null(n);
	assert_int_equal(*((int *)n->value), b);
	n = n->next;
	assert_non_null(n);
	assert_null(n->value);
	assert_null(n->next);
	assert_ptr_equal(list->last, n);

	scion_list_free(list);
}

static void test_list_append_all_null(void **)
{
	struct scion_list *list = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	int a = 1;
	int b = 2;
	scion_list_append(list, &a);
	scion_list_append(list, &b);

	scion_list_append_all(list, NULL);

	assert_uint_equal(list->size, 2);

	scion_list_free(list);
}

static void test_list_append_all(void **)
{
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

	assert_uint_equal(list_1->size, 4);

	struct scion_list_node *curr = list_1->first;
	assert_int_equal(*((int *)curr->value), 1);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 2);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 3);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 4);

	assert_uint_equal(list_2->size, 2);

	curr = list_2->first;
	assert_int_equal(*((int *)curr->value), 3);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 4);

	scion_list_free(list_1);
	scion_list_free(list_2);
}

static void test_list_pop(void **)
{
	assert_null(scion_list_pop(NULL));

	struct scion_list *list = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	assert_null(scion_list_pop(list));

	int a = 1;
	int b = 2;
	scion_list_append(list, &a);
	scion_list_append(list, &b);

	assert_int_equal(*((int *)scion_list_pop(list)), 1);
	assert_uint_equal(list->size, 1);

	assert_int_equal(*((int *)scion_list_pop(list)), 2);
	assert_uint_equal(list->size, 0);

	assert_null(scion_list_pop(list));
	assert_uint_equal(list->size, 0);

	scion_list_free(list);
}

static void test_list_reverse(void **)
{
	struct scion_list *list = scion_list_create(SCION_LIST_NO_FREE_VALUES);
	struct scion_list_node *curr;

	scion_list_reverse(list);
	assert_uint_equal(list->size, 0);

	int a = 1;
	int b = 2;
	int c = 3;
	int d = 4;

	// 1 element
	scion_list_append(list, &a);
	scion_list_reverse(list);
	assert_uint_equal(list->size, 1);
	assert_int_equal(*((int *)list->first->value), 1);

	// 2 elements
	scion_list_append(list, &b);
	scion_list_reverse(list);
	assert_uint_equal(list->size, 2);
	curr = list->first;
	assert_int_equal(*((int *)curr->value), 2);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 1);

	scion_list_reverse(list);
	assert_uint_equal(list->size, 2);
	curr = list->first;
	assert_int_equal(*((int *)curr->value), 1);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 2);

	// 3 elements
	scion_list_append(list, &c);
	scion_list_reverse(list);
	assert_uint_equal(list->size, 3);
	curr = list->first;
	assert_int_equal(*((int *)curr->value), 3);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 2);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 1);

	scion_list_reverse(list);
	assert_uint_equal(list->size, 3);
	curr = list->first;
	assert_int_equal(*((int *)curr->value), 1);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 2);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 3);

	// 4 elements
	scion_list_append(list, &d);
	scion_list_reverse(list);
	assert_uint_equal(list->size, 4);
	curr = list->first;
	assert_int_equal(*((int *)curr->value), 4);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 3);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 2);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 1);

	scion_list_reverse(list);
	assert_uint_equal(list->size, 4);
	curr = list->first;
	assert_int_equal(*((int *)curr->value), 1);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 2);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 3);
	curr = curr->next;
	assert_int_equal(*((int *)curr->value), 4);

	scion_list_free(list);
}

// Warning: This test produces false positives with (negligible) probability of 1 / 2^64.
static void test_list_free(void **)
{
	struct scion_list *list = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	uint64_t random_val = ((uint64_t)rand() << 32) | ((uint64_t)rand());
	uint64_t *heap_memory = malloc(sizeof(*heap_memory));
	*heap_memory = random_val;
	scion_list_append(list, heap_memory);

	scion_list_free(list);

	// Check that heap_memory is not freed
	pid_t pid = fork();
	assert_true(pid >= 0);

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

		assert_true(status == EXIT_SUCCESS);
	}

	free(heap_memory);
}

static void test_list_free_value(void **)
{
	struct scion_list *list = scion_list_create(SCION_LIST_SIMPLE_FREE);

	uint64_t random_val = ((uint64_t)rand() << 32) | ((uint64_t)rand());
	uint64_t *heap_memory = malloc(sizeof(*heap_memory));
	*heap_memory = random_val;
	scion_list_append(list, heap_memory);

	scion_list_free(list);

	// Check that heap_memory is freed
	pid_t pid = fork();
	assert_true(pid >= 0);

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

		assert_true(status != EXIT_SUCCESS);
	}
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

static void test_list_free_value_custom(void **)
{
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
	assert_true(pid >= 0);

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

		assert_true(status != EXIT_SUCCESS);
	}
}

int run_list_tests(void)
{
	const struct CMUnitTest tests[] = {
		cmocka_unit_test(test_list_create),
		cmocka_unit_test(test_list_append),
		cmocka_unit_test(test_list_append_all),
		cmocka_unit_test(test_list_append_all_null),
		cmocka_unit_test(test_list_pop),
		cmocka_unit_test(test_list_reverse),
		cmocka_unit_test(test_list_free),
		cmocka_unit_test(test_list_free_value),
		cmocka_unit_test(test_list_free_value_custom),
	};
	return cmocka_run_group_tests(tests, NULL, NULL);
}
