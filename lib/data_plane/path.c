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

#include <assert.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/as_entry.h"
#include "common/hop_field.h"
#include "common/info_field.h"
#include "common/isd_as.h"
#include "control_plane/path_collection.h"
#include "data_plane/path.h"
#include "scion/scion_scmp.h"
#include "util/endian.h"
#include "util/list.h"

int scion_path_meta_hdr_init(struct scion_path_meta_hdr *hdr)
{
	assert(hdr);

	hdr->curr_inf = 0;
	hdr->curr_hf = 0;
	hdr->seg_len[0] = 0;
	hdr->seg_len[1] = 0;
	hdr->seg_len[2] = 0;
	return 0;
}

int scion_path_raw_init(struct scion_path_raw *raw_path, struct scion_path_meta_hdr *hdr,
	struct scion_list *info_fields, struct scion_list *hop_fields)
{
	assert(raw_path);
	assert(hdr);
	assert(info_fields);
	assert(hop_fields);
	int ret;

	raw_path->length = (uint16_t)(SCION_META_LEN + info_fields->size * SCION_INFO_LEN
								  + hop_fields->size * SCION_HOP_LEN);
	raw_path->raw = malloc(raw_path->length);
	ret = scion_path_serialize(hdr, info_fields, hop_fields, raw_path->raw);
	if (ret != 0) {
		free(raw_path->raw);
		raw_path->raw = NULL;
		return ret;
	}
	return 0;
}

void scion_path_raw_free(struct scion_path_raw *raw_path)
{
	if (raw_path == NULL) {
		return;
	}
	if (raw_path->raw != NULL) {
		free(raw_path->raw);
		raw_path->raw = NULL;
	}
	raw_path->length = 0;
	free(raw_path);
}

void scion_path_free(struct scion_path *path)
{
	if (path == NULL) {
		return;
	}

	if (path->raw_path != NULL) {
		scion_path_raw_free(path->raw_path);
		path->raw_path = NULL;
	}

	if (path->metadata != NULL) {
		scion_path_metadata_free(path->metadata);
		path->metadata = NULL;
	}

	free(path);
}

int scion_path_raw_reverse(struct scion_path_raw *path)
{
	assert(path);
	int ret;

	if (path->length == 0) {
		// Empty path
		return 0;
	}

	assert(path->raw);

	struct scion_path_meta_hdr hdr;
	struct scion_list *info_fields = scion_list_create(SCION_LIST_SIMPLE_FREE);
	struct scion_list *hop_fields = scion_list_create(SCION_LIST_SIMPLE_FREE);

	ret = scion_path_deserialize(path->raw, path->length, &hdr, info_fields, hop_fields);
	if (ret != 0) {
		goto cleanup_info_and_hop_fields;
	}

	// reverse info fields
	scion_list_reverse(info_fields);
	if (info_fields->size == 3) {
		uint8_t first_seg_len = hdr.seg_len[0];
		hdr.seg_len[0] = hdr.seg_len[2];
		hdr.seg_len[2] = first_seg_len;
	} else if (info_fields->size == 2) {
		uint8_t first_seg_len = hdr.seg_len[0];
		hdr.seg_len[0] = hdr.seg_len[1];
		hdr.seg_len[1] = first_seg_len;
	}

	// reverse cons dir flag
	struct scion_info_field *info;
	struct scion_list_node *curr = info_fields->first;
	while (curr) {
		info = curr->value;
		info->cons_dir = !(info->cons_dir);
		curr = curr->next;
	}

	// reverse hop fields
	scion_list_reverse(hop_fields);

	// Update curr_inf and curr_hf
	// We don't simply reset to 0, as it might not be 0 if we are not the last hop in the path.
	hdr.curr_inf = (uint8_t)(info_fields->size - hdr.curr_inf - 1);
	hdr.curr_hf = (uint8_t)(hop_fields->size - hdr.curr_hf - 1);

	ret = scion_path_serialize(&hdr, info_fields, hop_fields, path->raw);

cleanup_info_and_hop_fields:
	scion_list_free(info_fields);
	scion_list_free(hop_fields);

	return ret;
}

int scion_path_reverse(struct scion_path *path)
{
	assert(path);

	scion_ia src = path->src;
	path->src = path->dst;
	path->dst = src;

	if (path->path_type == SCION_PATH_TYPE_EMPTY) {
		// Nothing to change
		return 0;
	}

	if (path->path_type == SCION_PATH_TYPE_SCION) {
		int ret = scion_path_raw_reverse(path->raw_path);
		if (ret != 0) {
			return ret;
		}

		scion_path_metadata_free(path->metadata);
		path->metadata = NULL;
		return 0;
	}

	return SCION_ERR_PATH_TYPE_INVALID;
}

// The interface a packet enters the AS on, in the direction of travel. The interfaces of a hop field are named after
// the construction direction, so which one it is depends on the direction the segment is traversed in.
static uint16_t arrival_interface(const struct scion_info_field *info_field, const struct scion_hop_field *hop_field)
{
	return info_field->cons_dir ? hop_field->cons_ingress : hop_field->cons_egress;
}

// The interface a packet leaves the AS on, in the direction of travel.
static uint16_t departure_interface(const struct scion_info_field *info_field, const struct scion_hop_field *hop_field)
{
	return info_field->cons_dir ? hop_field->cons_egress : hop_field->cons_ingress;
}

// Determines whether two consecutive segments are joined at a shortcut, that is, whether the packet turns around in an
// AS without going through its core. The two hop fields of that AS then carry an interface towards the parent AS that
// is not used. Hop fields of a peering link are not affected.
static bool is_shortcut(const struct scion_info_field *info_field, const struct scion_hop_field *last_hop_field,
	const struct scion_info_field *next_info_field, const struct scion_hop_field *next_hop_field)
{
	return !info_field->peer && departure_interface(info_field, last_hop_field) != 0
		   && arrival_interface(next_info_field, next_hop_field) != 0;
}

int scion_path_set_router_alert(struct scion_path *path, size_t interface_index)
{
	assert(path);

	if (path->path_type != SCION_PATH_TYPE_SCION) {
		return SCION_ERR_PATH_TYPE_INVALID;
	}

	assert(path->raw_path);
	assert(path->raw_path->raw);

	struct scion_path_meta_hdr hdr;
	struct scion_list *info_fields = scion_list_create(SCION_LIST_SIMPLE_FREE);
	struct scion_list *hop_fields = scion_list_create(SCION_LIST_SIMPLE_FREE);

	int ret = scion_path_deserialize(path->raw_path->raw, path->raw_path->length, &hdr, info_fields, hop_fields);
	if (ret != 0) {
		goto cleanup;
	}

	for (struct scion_list_node *node = hop_fields->first; node != NULL; node = node->next) {
		struct scion_hop_field *hop_field = node->value;
		hop_field->ingress_router_alert = false;
		hop_field->egress_router_alert = false;
	}

	// The hop fields are in the order the packet travels, also in a segment that is not traversed in its
	// construction direction. Count the interfaces in that order, like the path metadata does.
	bool found = false;
	size_t index = 0;
	size_t first_hop = 0;
	for (size_t segment = 0; segment < info_fields->size && !found; segment++) {
		struct scion_info_field *info_field = scion_list_get(info_fields, segment);
		size_t segment_len = hdr.seg_len[segment];
		bool has_next_segment = segment + 1 < info_fields->size;

		for (size_t i = 0; i < segment_len && !found; i++) {
			struct scion_hop_field *hop_field = scion_list_get(hop_fields, first_hop + i);

			bool arrival_used = arrival_interface(info_field, hop_field) != 0;
			bool departure_used = departure_interface(info_field, hop_field) != 0;

			if (i == 0 && segment > 0) {
				struct scion_info_field *last_info_field = scion_list_get(info_fields, segment - 1);
				struct scion_hop_field *last_hop_field = scion_list_get(hop_fields, first_hop - 1);
				if (is_shortcut(last_info_field, last_hop_field, info_field, hop_field)) {
					arrival_used = false;
				}
			}
			if (i + 1 == segment_len && has_next_segment) {
				struct scion_info_field *next_info_field = scion_list_get(info_fields, segment + 1);
				struct scion_hop_field *next_hop_field
					= scion_list_get(hop_fields, first_hop + segment_len);
				if (is_shortcut(info_field, hop_field, next_info_field, next_hop_field)) {
					departure_used = false;
				}
			}

			// The ingress flag is for the router of the construction ingress interface, the egress flag for
			// the router of the construction egress interface.
			if (arrival_used) {
				if (index == interface_index) {
					hop_field->ingress_router_alert = info_field->cons_dir;
					hop_field->egress_router_alert = !info_field->cons_dir;
					found = true;
				}
				index++;
			}
			if (departure_used && !found) {
				if (index == interface_index) {
					hop_field->ingress_router_alert = !info_field->cons_dir;
					hop_field->egress_router_alert = info_field->cons_dir;
					found = true;
				}
				index++;
			}
		}

		first_hop += segment_len;
	}

	if (!found) {
		ret = SCION_ERR_INDEX_OUT_OF_RANGE;
		goto cleanup;
	}

	ret = scion_path_serialize(&hdr, info_fields, hop_fields, path->raw_path->raw);

cleanup:
	scion_list_free(info_fields);
	scion_list_free(hop_fields);

	return ret;
}

/*
 * ##################################################################
 * ######################## Print Functions #########################
 * ##################################################################
 */
void scion_path_print_interfaces(struct scion_path_interface *interfaces, size_t interfaces_len)
{
	if (!interfaces || interfaces_len == 0) {
		return;
	}

	// Print first AS
	struct scion_path_interface *intf = &interfaces[0];
	scion_ia_print(intf->ia);
	(void)printf(" %" PRIu64 ">", intf->id);

	// Print Intermediate ASes
	for (size_t i = 0; i < (interfaces_len - 2) / 2; i++) {
		struct scion_path_interface *in_intf = &interfaces[i * 2 + 1];
		struct scion_path_interface *out_intf = &interfaces[i * 2 + 2];
		(void)printf("%" PRIu64 " ", in_intf->id);
		scion_ia_print(in_intf->ia);
		(void)printf(" %" PRIu64 ">", out_intf->id);
	}

	// Print last AS
	intf = &interfaces[interfaces_len - 1];
	(void)printf("%" PRIu64 " ", intf->id);
	scion_ia_print(intf->ia);
}

void scion_path_print(const struct scion_path *path)
{
	if (!path) {
		return;
	}

	if (path->path_type == SCION_PATH_TYPE_EMPTY) {
		(void)printf("Hops: Empty Path\n");
	} else if (path->path_type == SCION_PATH_TYPE_SCION) {
		(void)printf("Hops: [");
		scion_path_print_interfaces(path->metadata->interfaces, path->metadata->interfaces_len);
		(void)printf("] MTU: %" PRIu32 "\n", path->metadata->mtu);
	}
}

size_t scion_path_get_numhops(const struct scion_path *path)
{
	assert(path != NULL);

	if (path->path_type == SCION_PATH_TYPE_EMPTY) {
		return 0;
	} else {
		return (path->metadata->interfaces_len / 2) + 1;
	}
}

const struct scion_path_metadata *scion_path_get_metadata(const struct scion_path *path)
{
	assert(path);

	return path->metadata;
}

/*
 * ##################################################################
 * ######################## Serialize Path ##########################
 * ##################################################################
 */

// scion_path_meta_hdr will be serialized to the following format:
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | C |  CurrHF   |    RSV    |  Seg0Len  |  Seg1Len  |  Seg2Len  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

int scion_path_meta_hdr_serialize(struct scion_path_meta_hdr *hdr, uint8_t *buf)
{
	assert(buf);
	assert(hdr);

	uint32_t line = ((uint32_t)hdr->curr_inf) << 30 | ((uint32_t)(hdr->curr_hf & 0x3f)) << 24;
	line |= ((uint32_t)(hdr->seg_len[0] & 0x3f)) << 12;
	line |= ((uint32_t)(hdr->seg_len[1] & 0x3f)) << 6;
	line |= ((uint32_t)(hdr->seg_len[2] & 0x3f));
	scion_store_be32(buf, line);
	return 0;
}

int scion_path_serialize(
	struct scion_path_meta_hdr *hdr, struct scion_list *info_fields, struct scion_list *hop_fields, uint8_t *buf)
{
	assert(buf);
	assert(hdr);
	assert(info_fields);
	assert(hop_fields);
	int ret;

	struct scion_list_node *curr;
	uint16_t offset = (uint16_t)SCION_META_LEN;

	ret = scion_path_meta_hdr_serialize(hdr, buf);
	if (ret != 0) {
		return ret;
	}

	curr = info_fields->first;
	while (curr) {
		struct scion_info_field *curr_info_field = curr->value;
		ret = scion_info_field_serialize(buf + offset, curr_info_field);
		if (ret != 0) {
			return ret;
		}
		curr = curr->next;
		offset += (uint16_t)SCION_INFO_LEN;
	}

	curr = hop_fields->first;
	while (curr) {
		struct scion_hop_field *curr_hop_field = curr->value;
		ret = scion_hop_field_serialize(buf + offset, curr_hop_field);
		if (ret != 0) {
			return ret;
		}
		curr = curr->next;
		offset += (uint16_t)SCION_HOP_LEN;
	}
	return 0;
}

/*
 * ##################################################################
 * ####################### Deserialize Path #########################
 * ##################################################################
 */

int scion_path_meta_hdr_deserialize(const uint8_t *buf, struct scion_path_meta_hdr *hdr)
{
	assert(buf);
	assert(hdr);

	uint32_t line = scion_load_be32(buf);
	hdr->curr_inf = (uint8_t)(line >> 30);
	hdr->curr_hf = (uint8_t)((line >> 24) & 0x3f);
	hdr->seg_len[0] = (uint8_t)((line >> 12) & 0x3f);
	hdr->seg_len[1] = (uint8_t)((line >> 6) & 0x3f);
	hdr->seg_len[2] = (uint8_t)(line & 0x3f);
	return 0;
}

int scion_path_deserialize(
	uint8_t *buf, size_t buf_len, struct scion_path_meta_hdr *hdr, struct scion_list *info_fields,
	struct scion_list *hop_fields)
{
	assert(buf);
	assert(hdr);
	assert(info_fields);
	assert(hop_fields);
	int ret;

	if (buf_len < SCION_META_LEN) {
		return SCION_ERR_NOT_ENOUGH_DATA;
	}

	ret = scion_path_meta_hdr_deserialize(buf, hdr);
	if (ret != 0) {
		return ret;
	}
	uint16_t offset = (uint16_t)SCION_META_LEN;

	uint8_t num_inf = 0;
	uint8_t num_hf = 0;
	// Calculate num_inf and num_hf
	for (int8_t i = 2; i >= 0; i--) {
		if ((hdr->seg_len[i] == 0) && (num_inf > 0)) {
			return SCION_ERR_META_HDR_INVALID;
		}
		if (hdr->seg_len[i] > 0 && num_inf == 0) {
			num_inf = (uint8_t)i + 1;
		}
		num_hf += hdr->seg_len[i];
	}

	if (buf_len < SCION_META_LEN + (size_t)num_inf * SCION_INFO_LEN + (size_t)num_hf * SCION_HOP_LEN) {
		return SCION_ERR_NOT_ENOUGH_DATA;
	}

	for (uint8_t i = 0; i < num_inf; i++) {
		struct scion_info_field *info = malloc(sizeof(*info));
		if (info == NULL) {
			return SCION_ERR_MEM_ALLOC_FAIL;
		}
		ret = scion_info_field_deserialize(buf + offset, info);
		if (ret != 0) {
			free(info);
			return ret;
		}
		scion_list_append(info_fields, info);
		offset += (uint16_t)SCION_INFO_LEN;
	}

	for (uint8_t i = 0; i < num_hf; i++) {
		struct scion_hop_field *hop = malloc(sizeof(*hop));
		if (hop == NULL) {
			return SCION_ERR_MEM_ALLOC_FAIL;
		}
		ret = scion_hop_field_deserialize(buf + offset, hop);
		if (ret != 0) {
			free(hop);
			return ret;
		}
		scion_list_append(hop_fields, hop);
		offset += (uint16_t)SCION_HOP_LEN;
	}
	return 0;
}

void scion_path_print_metadata(const struct scion_path *path)
{
	scion_path_metadata_print(path->metadata);
}
