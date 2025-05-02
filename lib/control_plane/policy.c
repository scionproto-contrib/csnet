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

#include "policy.h"

#include <common/path_collection.h>

static int compare_mtu(struct scion_path *path_one, struct scion_path *path_two)
{
	uint32_t mtu_one = scion_path_get_mtu(path_one);
	uint32_t mtu_two = scion_path_get_mtu(path_two);

	return (mtu_one > mtu_two) - (mtu_one < mtu_two);
}

static void highest_mtu_filter(struct scion_path_collection *paths)
{
	scion_path_collection_sort(paths, compare_mtu, /* ascending */ false);
}
const struct scion_policy scion_policy_highest_mtu = { .filter = highest_mtu_filter };

static int compare_hops(struct scion_path *path_one, struct scion_path *path_two)
{
	size_t hops_one = scion_path_get_hops(path_one);
	size_t hops_two = scion_path_get_hops(path_two);

	return (hops_one > hops_two) - (hops_one < hops_two);
}

static void least_hops_filter(struct scion_path_collection *paths)
{
	scion_path_collection_sort(paths, compare_hops, /* ascending */ true);
}
const struct scion_policy scion_policy_least_hops = { .filter = least_hops_filter };
