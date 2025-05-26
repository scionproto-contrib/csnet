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

#pragma once

int scion_test_list_create(void);
int scion_test_list_append(void);
int scion_test_list_append_all(void);
int scion_test_list_append_all_null(void);
int scion_test_list_pop(void);
int scion_test_list_reverse(void);
int scion_test_list_free(void);
int scion_test_list_free_value(void);
int scion_test_list_free_value_custom(void);
