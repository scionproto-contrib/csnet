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
#include "common/path_collection.h"

#include <stdio.h>
#include <time.h>
#include <util/map.h>

static int compare_hops(struct scion_path *path_one, struct scion_path *path_two, void *ctx)
{
	(void)ctx;
	size_t hops_one = scion_path_get_hops(path_one);
	size_t hops_two = scion_path_get_hops(path_two);

	return (hops_one > hops_two) - (hops_one < hops_two);
}

static void least_hops_filter(struct scion_path_collection *paths)
{
	scion_path_collection_sort(
		paths, (struct scion_path_comparator){ .fn = (scion_path_comparator_fn)compare_hops, .ascending = true });
}
const struct scion_policy scion_policy_least_hops = { .filter = least_hops_filter };

static int compare_mtu(struct scion_path *path_one, struct scion_path *path_two, void *ctx)
{
	(void)ctx;
	uint32_t mtu_one = scion_path_get_mtu(path_one);
	uint32_t mtu_two = scion_path_get_mtu(path_two);

	int ret = (mtu_one > mtu_two) - (mtu_one < mtu_two);

	if (ret == 0) {
		// use hop count as secondary sorting criteria
		return -compare_hops(path_one, path_two, NULL);
	}

	return ret;
}

static void highest_mtu_filter(struct scion_path_collection *paths)
{
	scion_path_collection_sort(
		paths, (struct scion_path_comparator){ .fn = (scion_path_comparator_fn)compare_mtu, .ascending = false });
}
const struct scion_policy scion_policy_highest_mtu = { .filter = highest_mtu_filter };

static int compare_latencies(
	struct scion_path *path_one, struct scion_path *path_two, struct scion_map *path_total_latencies)
{
	struct timeval *latency_one = scion_map_get(path_total_latencies, &path_one);
	struct timeval *latency_two = scion_map_get(path_total_latencies, &path_two);

	if (latency_one && latency_two) {
		if (timercmp(latency_one, latency_two, >)) {
			return 1;
		}

		if (timercmp(latency_one, latency_two, <)) {
			return -1;
		}
	} else {
		if (latency_one) {
			return -1;
		}

		if (latency_two) {
			return 1;
		}
	}

	// use hop count as secondary sorting criteria
	return compare_hops(path_one, path_two, NULL);
}

static void lowest_latency_filter(struct scion_path_collection *paths)
{
	struct scion_map *path_total_latencies = scion_map_create(sizeof(struct scion_path *), SCION_MAP_SIMPLE_FREE);

	struct scion_linked_list_node *current = paths->list->first;
	while (current) {
		struct scion_path *path = current->value;

		struct timeval *total_latency = calloc(1, sizeof(*total_latency));

		if (path->metadata != NULL && path->metadata->latencies != NULL) {
			for (size_t i = 0; i < scion_list_size(path->metadata->interfaces); i++) {
				struct timeval latency = path->metadata->latencies[i];

				// Set total latency to unknown if entry is missing
				if (SCION_PATH_METADATA_LATENCY_IS_UNSET(latency)) {
					*total_latency = (struct timeval){ .tv_sec = 0, .tv_usec = -1 };
					break;
				}

				timeradd(total_latency, &latency, total_latency);
			}

			if (total_latency->tv_usec != -1) {
				scion_map_put(path_total_latencies, &path, total_latency);
			}
		}

		current = current->next;
	}

	scion_path_collection_sort(
		paths, (struct scion_path_comparator){
				   .fn = (scion_path_comparator_fn)compare_latencies, .ctx = path_total_latencies, .ascending = true });

	scion_map_free(path_total_latencies);
}
const struct scion_policy scion_policy_lowest_latency = { .filter = lowest_latency_filter };

static int compare_bandwidths(
	struct scion_path *path_one, struct scion_path *path_two, struct scion_map *path_bandwidths)
{
	uint64_t *bandwidth_one = scion_map_get(path_bandwidths, &path_one);
	uint64_t *bandwidth_two = scion_map_get(path_bandwidths, &path_two);

	if (bandwidth_one && bandwidth_two) {
		int cmp = (*bandwidth_one > *bandwidth_two) - (*bandwidth_two > *bandwidth_one);

		if (cmp != 0) {
			return cmp;
		}
	} else {
		if (bandwidth_one) {
			return 1;
		}

		if (bandwidth_two) {
			return -1;
		}
	}

	// use hop count as secondary sorting criteria
	return -compare_hops(path_one, path_two, NULL);
}

static void highest_bandwidth_filter(struct scion_path_collection *paths)
{
	struct scion_map *path_bandwidths = scion_map_create(sizeof(struct scion_path *), SCION_MAP_SIMPLE_FREE);

	struct scion_linked_list_node *current = paths->list->first;
	while (current) {
		struct scion_path *path = current->value;

		uint64_t *min_bandwidth = malloc(sizeof(*min_bandwidth));
		*min_bandwidth = UINT64_MAX;

		if (path->metadata != NULL && path->metadata->bandwidths != NULL) {
			for (size_t i = 0; i < scion_list_size(path->metadata->interfaces); i++) {
				uint64_t bandwidth = path->metadata->bandwidths[i];

				// Set min bandwidth to 0 if entry is missing
				if (SCION_PATH_METADATA_BANDWIDTH_IS_UNSET(bandwidth)) {
					*min_bandwidth = UINT64_MAX;
					break;
				}

				if (bandwidth < *min_bandwidth) {
					*min_bandwidth = bandwidth;
				}
			}

			if (*min_bandwidth != UINT64_MAX) {
				scion_map_put(path_bandwidths, &path, min_bandwidth);
			}
		}

		current = current->next;
	}

	scion_path_collection_sort(
		paths, (struct scion_path_comparator){
				   .fn = (scion_path_comparator_fn)compare_bandwidths, .ctx = path_bandwidths, .ascending = false });

	scion_map_free(path_bandwidths);
}
const struct scion_policy scion_policy_highest_bandwidth = { .filter = highest_bandwidth_filter };
