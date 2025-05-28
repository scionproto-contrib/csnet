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

#include <stdint.h>

#include "common/isd_as.h"
#include "common/path_segment.h"
#include "scion/scion.h"

struct scion_split_segments {
	bool has_up;
	scion_ia up_src;
	scion_ia up_dst;
	bool has_core;
	scion_ia core_src;
	scion_ia core_dst;
	bool has_down;
	scion_ia down_src;
	scion_ia down_dst;
};

struct scion_path_segment_list {
	struct scion_path_segment **list;
	size_t length;
	enum scion_segment_type type; // TODO: Can likely be removed? never really needed?
};

/*
 * FUNCTION: scion_split_segments
 * ---------------
 * Splits the segment request from a source AS to a Destination AS into an UP segment request,
 * a CORE segment request and a DOWN segment request. Depending on the case, not all segments are needed.
 *
 * Cases:
 * (1) Source and destination are in the same AS.
 *      Result: empty path, we are in the same AS.
 *
 * (2) Source and destination are Core ASes.
 *      Result: [(src to dst, CORE)]
 *
 * (3) Source and destination are in the same ISD. Only the source is a Core AS.
 *      Result: [(src to dst_wildcard, CORE), (dst_wildcard to dst, DOWN)]
 *
 *      - Potential Optimization if we can determine that source is the only Core AS in the ISD:
 *        [(src to dst, DOWN)]
 *
 * (4) Source and destination are in the same ISD. Only the destination is a Core AS.
 *      Result: [(src to dst_wildcard, UP), (dst_wildcard to dst, CORE)]
 *
 *      - Potential Optimization if we can determine that destination is the only Core AS in the ISD:
 *        [(src to dst, UP)]
 *
 * (5) Source and destination are in the same ISD. Neither are Core ASes.
 *      Result: [(src to src_wildcard, UP), (src_wildcard to dst_wildcard, CORE), (dst_wildcard to dst, DOWN)]
 *
 *      - Potential Optimization if we can determine that there is the only one Core AS in the ISD:
 *      [(src to src_wildcard, UP), (dst_wildcard to dst, DOWN)]
 *
 * (6) Source and destination are not in the same ISD. Only the source is a Core AS.
 *      Result: [(src to dst_wildcard, CORE), (dst_wildcard to dst, DOWN)]
 *
 * (7) Source and destination are not in the same ISD. Only the destination is a Core AS.
 *      Result: [(src to src_wildcard, UP), (src_wildcard to dst, CORE)]
 *
 * (8) Source and destination are not in the same ISD. Neither are Core ASes.
 *      Result: [(src to src_wildcard, UP), (src_wildcard to dst_wildcard, CORE), (dst_wildcard to dst, DOWN)]
 *
 * Arguments:
 *      - ScionIA src: source AS.
 * 		- bool src_is_core: true if src AS is a core AS, false otherwise.
 *      - ScionIA dst: destination AS.
 * 		- bool dst_is_core: true if dst AS is a core AS, false otherwise.
 *      - struct scion_split_segments *split_seg: Pointer to a scion_split_segments struct into which the result will be
 * stored. Returns:
 *      - An integer status code, 0 for success or an error code as defined in error.h.
 */
int scion_split_segments(
	scion_ia src, bool src_is_core, scion_ia dst, bool dst_is_core, struct scion_split_segments *split_seg);

/*
 * FUNCTION: scion_path_segments_lookup
 * -----------------
 *  Looks up the path segments required to build a path between a given source AS and destination AS
 *  by making the required gRPC calls to a SCION control server.
 *
 * Arguments:
 * 		- const char *hostname: Hostname of the control server.
 * 		- const char *ip: IP of the control server.
 * 		- int port: Port on which the control server is reachable.
 * 		- ScionIA src: source AS.
 *      - ScionIA dst: destination AS.
 * 		- struct scion_path_segment_list *segments: Pointer to the scion_path_segment_list struct into which the result
 * will be saved.
 *
 * Returns:
 *      - An integer status code, 0 for success or an error code as defined in error.h.
 */
int scion_path_segments_lookup(
	struct scion_topology *topology, scion_ia src, scion_ia dst, struct scion_path_segment_list *segments);

/*
 * FUNCTION: scion_free_pathseglist_internal
 * -----------------
 *  Frees the internal members provided scion_path_segment_list, including the scion_path_segment structs.
 *
 * Arguments:
 * 		- struct scion_path_segment_list *pathseg_list: Pointer to a scion_path_segment_list struct.
 */
void scion_free_pathseglist_internal(struct scion_path_segment_list *pathseg_list);

/*
 * FUNCTION: scion_dst_core_check
 * -----------------
 * By making a Segment Lookup, we can figure out if the destination AS is a core or not.
 * We have the following cases:
 * (1): src and dst are in different ISDs:
 * 		--> if a direct lookup wildcard(src)->dst succeeds, then dst is a core, else it's not.
 * (2): src and dst are in same ISD:
 * 		--> if a direct lookup wildcard(src)->dst should always succeed! We check the value of key
 * 			in the map:
 * 				if key == 3 --> Core segment -> dst is core,
 * 				if key != 3 --> Non-core segment -> dst is non-core,
 * 				if map is empty --> form our AS no core segments with destination dst make sense
 * 					(i.e. they don't exist), but as it succeeds, dst is core.
 *
 * Arguments:
 * 		- const char *hostname: Hostname of the control server.
 * 		- const char *ip: IP of the control server.
 * 		- int port: Port on which the control server is reachable.
 * 		- ScionIA src: source AS.
 *      - ScionIA dst: destination AS.
 *
 * Returns:
 *      - An integer status code, 0 if dst is a non-core AS, 1 if dst is a core AS and
 * 		  otherwise an error code as defined in error.h.
 */
int scion_dst_core_check(struct scion_topology *topology, scion_ia src, scion_ia dst);

size_t scion_pathsegment_list_byte_size(struct scion_path_segment_list *pathseglist);
