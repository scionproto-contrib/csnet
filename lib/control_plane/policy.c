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

#include <stdio.h>
#include <time.h>

#include "common/path_collection.h"
#include "policy.h"
#include "util/map.h"

#define PATH_KEY_SIZE 8

static int compare_hops(struct scion_path *path_one, struct scion_path *path_two, void *ctx)
{
	(void)ctx;
	size_t hops_one = scion_path_get_hops(path_one);
	size_t hops_two = scion_path_get_hops(path_two);

	return (hops_one > hops_two) - (hops_one < hops_two);
}

static void sort_least_hops(struct scion_path_collection *paths, void *ctx)
{
	(void)ctx;
	scion_path_collection_sort(
		paths, (struct scion_path_comparator){ .fn = (scion_path_comparator_fn)compare_hops, .ascending = true });
}
const struct scion_policy scion_policy_least_hops = { .fn = sort_least_hops, .ctx = NULL };

static int compare_mtu(struct scion_path *path_one, struct scion_path *path_two, void *ctx)
{
	(void)ctx;
	uint32_t mtu_one = scion_path_get_metadata(path_one)->mtu;
	uint32_t mtu_two = scion_path_get_metadata(path_two)->mtu;

	int ret = (mtu_one > mtu_two) - (mtu_one < mtu_two);

	if (ret == 0) {
		// use hop count as secondary sorting criteria
		return -compare_hops(path_one, path_two, NULL);
	}

	return ret;
}

static void sort_highest_mtu(struct scion_path_collection *paths, void *ctx)
{
	(void)ctx;

	scion_path_collection_sort(
		paths, (struct scion_path_comparator){ .fn = (scion_path_comparator_fn)compare_mtu, .ascending = false });
}
const struct scion_policy scion_policy_highest_mtu = { .fn = sort_highest_mtu, .ctx = NULL };

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

static void sort_lowest_latency(struct scion_path_collection *path_collection, void *ctx)
{
	(void)ctx;

	struct scion_map *path_total_latencies = scion_map_create(
		(struct scion_map_key_config){ .size = PATH_KEY_SIZE, .serialize = NULL }, SCION_MAP_SIMPLE_FREE);

	size_t paths_len;
	struct scion_path **paths = scion_path_collection_as_array(path_collection, &paths_len);

	for (size_t i = 0; i < paths_len; i++) {
		struct scion_path *path = paths[i];
		struct scion_path_metadata *metadata = path->metadata;

		if (metadata != NULL && metadata->latencies != NULL) {
			struct timeval *total_latency = calloc(1, sizeof(*total_latency));

			for (size_t j = 0; j < metadata->interfaces_len; j++) {
				struct timeval latency = metadata->latencies[j];

				// Set total latency to unknown if entry is missing
				if (SCION_PATH_METADATA_LATENCY_IS_UNSET(latency)) {
					*total_latency = (struct timeval){ .tv_sec = 0, .tv_usec = -1 };
					break;
				}

				timeradd(total_latency, &latency, total_latency);
			}

			if (total_latency->tv_usec != -1) {
				scion_map_put(path_total_latencies, &path, total_latency);
			} else {
				free(total_latency);
			}
		}
	}

	scion_path_collection_sort(path_collection,
		(struct scion_path_comparator){
			.fn = (scion_path_comparator_fn)compare_latencies, .ctx = path_total_latencies, .ascending = true });

	free(paths);
	scion_map_free(path_total_latencies);
}
const struct scion_policy scion_policy_lowest_latency = { .fn = sort_lowest_latency, .ctx = NULL };

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

static void sort_highest_bandwidth(struct scion_path_collection *path_collection, void *ctx)
{
	(void)ctx;

	struct scion_map *path_bandwidths = scion_map_create(
		(struct scion_map_key_config){ .size = PATH_KEY_SIZE, .serialize = NULL }, SCION_MAP_SIMPLE_FREE);

	size_t paths_len;
	struct scion_path **paths = scion_path_collection_as_array(path_collection, &paths_len);

	for (size_t i = 0; i < paths_len; i++) {
		struct scion_path *path = paths[i];
		struct scion_path_metadata *metadata = path->metadata;

		if (metadata != NULL && metadata->bandwidths != NULL) {
			uint64_t *min_bandwidth = malloc(sizeof(*min_bandwidth));
			*min_bandwidth = UINT64_MAX;

			for (size_t j = 0; j < metadata->interfaces_len; j++) {
				uint64_t bandwidth = metadata->bandwidths[j];

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
			} else {
				free(min_bandwidth);
			}
		}
	}

	scion_path_collection_sort(path_collection,
		(struct scion_path_comparator){
			.fn = (scion_path_comparator_fn)compare_bandwidths, .ctx = path_bandwidths, .ascending = false });

	free(paths);
	scion_map_free(path_bandwidths);
}
const struct scion_policy scion_policy_highest_bandwidth = { .fn = sort_highest_bandwidth, .ctx = NULL };

static bool has_min_mtu(struct scion_path *path, uint32_t *mtu)
{
	return scion_path_get_metadata(path)->mtu >= *mtu;
}

static void filter_min_mtu(struct scion_path_collection *path_collection, uint32_t *mtu)
{
	scion_path_collection_filter(
		path_collection, (struct scion_path_predicate){ .fn = (scion_path_predicate_fn)has_min_mtu, .ctx = mtu });
}

struct scion_policy scion_policy_min_mtu(uint32_t *mtu)
{
	return (struct scion_policy){ .fn = (scion_policy_fn)filter_min_mtu, .ctx = mtu };
}
