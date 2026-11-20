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

#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <time.h>

#include "common/isd_as.h"
#include "common/path_segment.h"
#include "control_plane/graph.h"
#include "control_plane/network_trcs.h"
#include "control_plane/segment.h"
#include "proto/control_plane/v1/cppki.pb-c.h"
#include "proto/control_plane/v1/seg.pb-c.h"
#include "util/http2_rpc.h"
#include "util/map.h"

#define SEGMENTS_PATH "/proto.control_plane.v1.SegmentLookupService/Segments"
#define INITIAL_RPC_OUTPUT_BUFFER_SIZE (2 << 15)

#define INTERFACE_KEY_SIZE 8

static int set_split_seg(struct scion_split_segments *split_seg, bool has_up, scion_ia up_src, scion_ia up_dst,
	bool has_core, scion_ia core_src, scion_ia core_dst, bool has_down, scion_ia down_src, scion_ia down_dst)
{
	assert(split_seg);

	split_seg->has_up = has_up;
	split_seg->up_src = up_src;
	split_seg->up_dst = up_dst;
	split_seg->has_core = has_core;
	split_seg->core_src = core_src;
	split_seg->core_dst = core_dst;
	split_seg->has_down = has_down;
	split_seg->down_src = down_src;
	split_seg->down_dst = down_dst;
	return 0;
}

/*
 * Splits the segment request from a source AS to a Destionation AS into an UP segment request,
 * an CORE segment request and a DOWN segment request. Depending on the case, not all segments are needed.
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
	scion_ia src, bool src_is_core, scion_ia dst, bool dst_is_core, struct scion_split_segments *split_seg)
{
	assert(split_seg);
	int ret;

	if (src == dst) {
		// Case (1)
		ret = set_split_seg(split_seg, false, 0, 0, false, 0, 0, false, 0, 0);
		return ret;
	}

	if (src_is_core && dst_is_core) {
		// Case (2)
		ret = set_split_seg(split_seg, false, 0, 0, true, src, dst, false, 0, 0);
		return ret;
	}

	scion_isd src_isd = scion_ia_get_isd(src);
	scion_isd dst_isd = scion_ia_get_isd(dst);

	if (src_isd == dst_isd) {
		scion_ia wildcard = scion_ia_to_wildcard(src);
		if (src_is_core) {
			// Case (3), Optimizations not yet handled
			ret = set_split_seg(split_seg, false, 0, 0, true, src, wildcard, true, wildcard, dst);
			return ret;
		} else if (dst_is_core) {
			// Case (4), Optimizations not yet handled
			ret = set_split_seg(split_seg, true, src, wildcard, true, wildcard, dst, false, 0, 0);
			return ret;
		} else {
			// Case (5), Optimizations not yet handled
			ret = set_split_seg(split_seg, true, src, wildcard, true, wildcard, wildcard, true, wildcard, dst);
			return ret;
		}
	} else {
		if (src_is_core) {
			// Case (6)
			scion_ia dst_wildcard = scion_ia_to_wildcard(dst);
			ret = set_split_seg(split_seg, false, 0, 0, true, src, dst_wildcard, true, dst_wildcard, dst);
			return ret;
		} else if (dst_is_core) {
			// Case (7)
			scion_ia src_wildcard = scion_ia_to_wildcard(src);
			ret = set_split_seg(split_seg, true, src, src_wildcard, true, src_wildcard, dst, false, 0, 0);
			return ret;
		} else {
			// Case (8)
			scion_ia src_wildcard = scion_ia_to_wildcard(src);
			scion_ia dst_wildcard = scion_ia_to_wildcard(dst);
			ret = set_split_seg(
				split_seg, true, src, src_wildcard, true, src_wildcard, dst_wildcard, true, dst_wildcard, dst);
			return ret;
		}
	}
}

// The certificate chains that verified the AS entries of the segments of one lookup
struct chain_cache {
	struct scion_cert_chain **chains;
	size_t num_chains;
};

static void chain_cache_free_members(struct chain_cache *cache)
{
	for (size_t i = 0; i < cache->num_chains; i++) {
		scion_cert_chain_free_members(cache->chains[i]);
		free(cache->chains[i]);
	}
	free(cache->chains);
}

// Returns the verified chain of an AS with a subject key ID, from the cache or else from the control service
static int get_chain(const struct scion_network *net, struct chain_cache *cache,
	const Proto__ControlPlane__V1__VerificationKeyID *key_id, time_t now, struct scion_cert_chain **chain)
{
	for (size_t i = 0; i < cache->num_chains; i++) {
		const mbedtls_x509_buf *subject_key_id = &cache->chains[i]->certs.subject_key_id;
		if (cache->chains[i]->ia == key_id->isd_as && subject_key_id->len == key_id->subject_key_id.len
			&& memcmp(subject_key_id->p, key_id->subject_key_id.data, subject_key_id->len) == 0) {
			*chain = cache->chains[i];
			return 0;
		}
	}

	struct scion_cert_chain **chains = realloc(cache->chains, (cache->num_chains + 1) * sizeof(*chains));
	if (chains == NULL) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}
	cache->chains = chains;

	struct scion_cert_chain *new_chain = malloc(sizeof(*new_chain));
	if (new_chain == NULL) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}

	int ret = scion_network_fetch_chain(
		net, key_id->isd_as, key_id->subject_key_id.data, key_id->subject_key_id.len, now, new_chain);
	if (ret != 0) {
		free(new_chain);
		return ret;
	}

	cache->chains[cache->num_chains++] = new_chain;
	*chain = new_chain;
	return 0;
}

/*
 * Verifies the signature of an AS entry over the parts of its signature input: its header and body, and the associated
 * data in the remaining parts.
 */
static int verify_as_entry(const struct scion_network *net, struct chain_cache *cache,
	const Proto__Crypto__V1__SignedMessage *signed_msg, const struct iovec *parts, size_t num_parts, time_t now)
{
	size_t associated_data_len = 0;
	for (size_t i = 1; i < num_parts; i++) {
		associated_data_len += parts[i].iov_len;
	}

	Proto__Crypto__V1__HeaderAndBodyInternal *header_and_body = proto__crypto__v1__header_and_body_internal__unpack(
		NULL, signed_msg->header_and_body.len, signed_msg->header_and_body.data);
	if (header_and_body == NULL) {
		return SCION_ERR_SIGNATURE_INVALID;
	}

	int ret = SCION_ERR_SIGNATURE_INVALID;
	Proto__Crypto__V1__Header *header = proto__crypto__v1__header__unpack(
		NULL, header_and_body->header.len, header_and_body->header.data);
	Proto__ControlPlane__V1__ASEntrySignedBody *body = proto__control_plane__v1__asentry_signed_body__unpack(
		NULL, header_and_body->body.len, header_and_body->body.data);
	Proto__ControlPlane__V1__VerificationKeyID *key_id = NULL;
	if (header != NULL) {
		key_id = proto__control_plane__v1__verification_key_id__unpack(
			NULL, header->verification_key_id.len, header->verification_key_id.data);
	}

	// The AS that created the entry signed it, with the associated data that the header announces
	if (header == NULL || body == NULL || key_id == NULL || key_id->isd_as != body->isd_as
		|| header->associated_data_length < 0 || (size_t)header->associated_data_length != associated_data_len) {
		goto cleanup;
	}

	struct scion_cert_chain *chain;
	ret = get_chain(net, cache, key_id, now, &chain);
	if (ret != 0) {
		goto cleanup;
	}

	ret = scion_cert_chain_verify_signature(chain, (enum scion_signature_algorithm)header->signature_algorithm, parts,
		num_parts, signed_msg->signature.data, signed_msg->signature.len);

cleanup:
	proto__control_plane__v1__verification_key_id__free_unpacked(key_id, NULL);
	proto__control_plane__v1__asentry_signed_body__free_unpacked(body, NULL);
	proto__crypto__v1__header__free_unpacked(header, NULL);
	proto__crypto__v1__header_and_body_internal__free_unpacked(header_and_body, NULL);
	return ret;
}

/*
 * Verifies the signatures of the AS entries of a segment. The signature input of an AS entry is its header and body,
 * followed by the segment information and the header, body and signature of each AS entry before it.
 */
static int verify_segment(const struct scion_network *net, struct chain_cache *cache,
	const Proto__ControlPlane__V1__PathSegment *segment, time_t now)
{
	if (segment->n_as_entries == 0) {
		return SCION_ERR_SIGNATURE_INVALID;
	}

	struct iovec *parts = malloc((2 + 2 * segment->n_as_entries) * sizeof(*parts));
	if (parts == NULL) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}
	parts[1] = (struct iovec){ .iov_base = segment->segment_info.data, .iov_len = segment->segment_info.len };

	int ret = 0;
	for (size_t i = 0; i < segment->n_as_entries && ret == 0; i++) {
		const Proto__Crypto__V1__SignedMessage *signed_msg = segment->as_entries[i]->signed_;
		if (signed_msg == NULL) {
			ret = SCION_ERR_SIGNATURE_INVALID;
			break;
		}

		parts[0] = (struct iovec){ .iov_base = signed_msg->header_and_body.data,
			.iov_len = signed_msg->header_and_body.len };
		ret = verify_as_entry(net, cache, signed_msg, parts, 2 + 2 * i, now);

		parts[2 + 2 * i] = parts[0];
		parts[3 + 2 * i] = (struct iovec){ .iov_base = signed_msg->signature.data,
			.iov_len = signed_msg->signature.len };
	}

	free(parts);
	return ret;
}

static int protobuf_to_path_segments(const struct scion_network *net,
	Proto__ControlPlane__V1__SegmentsResponse *pb_seg_response, struct scion_path_segment_list *result_list)
{
	assert(net);
	assert(pb_seg_response);
	assert(pb_seg_response->segments);
	assert(result_list);

	result_list->type = (enum scion_segment_type)pb_seg_response->segments[0]->key;
	Proto__ControlPlane__V1__SegmentsResponse__Segments *pb_segs_list = pb_seg_response->segments[0]->value;

	assert(pb_segs_list);
	assert(pb_segs_list->segments);

	// Without TRCs, the segments cannot be verified, see scion_network_load_trcs()
	bool verify = scion_network_has_trcs(net);
	static atomic_flag warned = ATOMIC_FLAG_INIT;
	if (!verify && !atomic_flag_test_and_set(&warned)) {
		(void)fprintf(stderr, "WARNING: the path segments are not verified, as the network has no TRCs\n");
	}

	int ret = 0;
	time_t now = time(NULL);
	struct chain_cache cache = { 0 };

	result_list->length = 0;
	result_list->list = malloc(pb_segs_list->n_segments * sizeof(*result_list->list));
	for (size_t i = 0; i < pb_segs_list->n_segments; i++) {
		Proto__ControlPlane__V1__PathSegment *curr_pb_seg = pb_segs_list->segments[i];

		if (verify) {
			ret = verify_segment(net, &cache, curr_pb_seg, now);
			if (ret == SCION_ERR_MEM_ALLOC_FAIL) {
				break;
			}
			if (ret != 0) {
				(void)fprintf(stderr, "Ignoring a path segment that cannot be verified (%s, code %d)\n",
					scion_strerror(ret), ret);
				ret = 0;
				continue;
			}
		}

		struct scion_path_segment *pathseg = malloc(sizeof(*pathseg));
		result_list->list[result_list->length++] = pathseg;

		// SegmentInfo
		Proto__ControlPlane__V1__SegmentInformation *info = proto__control_plane__v1__segment_information__unpack(
			NULL, curr_pb_seg->segment_info.len, curr_pb_seg->segment_info.data);
		pathseg->info.timestamp = info->timestamp;
		// Note: In the GO proto definition the segment ID is uint32. However, in the SCION dataplane specification the
		// segment ID is only 16-bit wide. Hence, I cast it down to 16-bit here.
		pathseg->info.segment_id = (uint16_t)info->segment_id;
		proto__control_plane__v1__segment_information__free_unpacked(info, NULL);

		// ASEntries
		pathseg->as_entries_length = curr_pb_seg->n_as_entries;
		pathseg->as_entries = malloc(pathseg->as_entries_length * sizeof(*pathseg->as_entries));

		assert(curr_pb_seg->n_as_entries == 0 || curr_pb_seg->as_entries);

		for (size_t j = 0; j < pathseg->as_entries_length; j++) {
			Proto__ControlPlane__V1__ASEntry *curr_pb_as_entry = curr_pb_seg->as_entries[j];
			ProtobufCBinaryData raw_signed_header_body = curr_pb_as_entry->signed_->header_and_body;

			Proto__Crypto__V1__HeaderAndBodyInternal *hb = proto__crypto__v1__header_and_body_internal__unpack(
				NULL, raw_signed_header_body.len, raw_signed_header_body.data);
			Proto__ControlPlane__V1__ASEntrySignedBody *pb_as_entry
				= proto__control_plane__v1__asentry_signed_body__unpack(NULL, hb->body.len, hb->body.data);

			struct scion_as_entry *curr_as_entry = calloc(1, sizeof(*curr_as_entry));
			pathseg->as_entries[j] = curr_as_entry;
			// local IA
			curr_as_entry->local = pb_as_entry->isd_as;
			// next IA
			curr_as_entry->next = pb_as_entry->next_isd_as;
			// HopEntry
			curr_as_entry->hop_entry.hop_field.exp_time = (uint8_t)pb_as_entry->hop_entry->hop_field->exp_time;
			curr_as_entry->hop_entry.hop_field.cons_ingress = (uint16_t)pb_as_entry->hop_entry->hop_field->ingress;
			curr_as_entry->hop_entry.hop_field.cons_egress = (uint16_t)pb_as_entry->hop_entry->hop_field->egress;
			(void)memcpy(curr_as_entry->hop_entry.hop_field.mac, pb_as_entry->hop_entry->hop_field->mac.data,
				pb_as_entry->hop_entry->hop_field->mac.len);
			curr_as_entry->hop_entry.ingress_mtu = (uint16_t)pb_as_entry->hop_entry->ingress_mtu;
			// Peer Entries
			if (pb_as_entry->n_peer_entries > 0) {
				curr_as_entry->peer_entries_length = (uint16_t)pb_as_entry->n_peer_entries;
				curr_as_entry->peer_entries = malloc(
					curr_as_entry->peer_entries_length * sizeof(*curr_as_entry->peer_entries));
				for (uint16_t k = 0; k < curr_as_entry->peer_entries_length; k++) {
					struct scion_peer_entry *curr_peer = malloc(sizeof(*curr_peer));
					curr_as_entry->peer_entries[k] = curr_peer;
					curr_peer->hopfield.exp_time = (uint8_t)pb_as_entry->peer_entries[k]->hop_field->exp_time;
					curr_peer->hopfield.cons_ingress = (uint16_t)pb_as_entry->peer_entries[k]->hop_field->ingress;
					curr_peer->hopfield.cons_egress = (uint16_t)pb_as_entry->peer_entries[k]->hop_field->egress;
					(void)memcpy(curr_peer->hopfield.mac, pb_as_entry->peer_entries[k]->hop_field->mac.data,
						pb_as_entry->peer_entries[k]->hop_field->mac.len);
					curr_peer->peer = (scion_ia)pb_as_entry->peer_entries[k]->peer_isd_as;
					curr_peer->peer_interface = (uint16_t)pb_as_entry->peer_entries[k]->peer_interface;
					curr_peer->peer_mtu = (uint16_t)pb_as_entry->peer_entries[k]->peer_mtu;
				}
			} else {
				curr_as_entry->peer_entries_length = 0;
				curr_as_entry->peer_entries = NULL;
			}
			// MTU
			curr_as_entry->mtu = (uint16_t)pb_as_entry->mtu;

			if (pb_as_entry->extensions != NULL) {
				Proto__ControlPlane__V1__StaticInfoExtension *pb_static_info = pb_as_entry->extensions->static_info;

				if (pb_static_info != NULL) {
					curr_as_entry->extensions.static_info = calloc(1, sizeof(*curr_as_entry->extensions.static_info));

					if (pb_static_info->latency != NULL) {
						struct scion_map *intra_latency = scion_map_create(
							(struct scion_map_key_config){ .size = INTERFACE_KEY_SIZE, .serialize = NULL },
							SCION_MAP_SIMPLE_FREE);
						for (size_t k = 0; k < pb_static_info->latency->n_intra; k++) {
							struct timeval *latency = malloc(sizeof(*latency));
							time_t seconds = pb_static_info->latency->intra[k]->value / 1000000;
							suseconds_t microseconds = pb_static_info->latency->intra[k]->value % 1000000;
							*latency = (struct timeval){ .tv_sec = seconds, .tv_usec = microseconds };
							scion_map_put(intra_latency, &pb_static_info->latency->intra[k]->key, latency);
						}

						struct scion_map *inter_latency = scion_map_create(
							(struct scion_map_key_config){ .size = INTERFACE_KEY_SIZE, .serialize = NULL },
							SCION_MAP_SIMPLE_FREE);

						for (size_t k = 0; k < pb_static_info->latency->n_inter; k++) {
							struct timeval *latency = malloc(sizeof(*latency));
							time_t seconds = pb_static_info->latency->inter[k]->value / 1000000;
							suseconds_t microseconds = pb_static_info->latency->inter[k]->value % 1000000;
							*latency = (struct timeval){ .tv_sec = seconds, .tv_usec = microseconds };
							scion_map_put(inter_latency, &pb_static_info->latency->inter[k]->key, latency);
						}

						curr_as_entry->extensions.static_info->latency = malloc(
							sizeof(*curr_as_entry->extensions.static_info->latency));
						curr_as_entry->extensions.static_info->latency->intra = intra_latency;
						curr_as_entry->extensions.static_info->latency->inter = inter_latency;
					}

					if (pb_static_info->bandwidth != NULL) {
						struct scion_map *intra_bandwidth = scion_map_create(
							(struct scion_map_key_config){ .size = INTERFACE_KEY_SIZE, .serialize = NULL },
							SCION_MAP_SIMPLE_FREE);
						for (size_t k = 0; k < pb_static_info->bandwidth->n_intra; k++) {
							uint64_t *bandwidth = malloc(sizeof(*bandwidth));
							*bandwidth = pb_static_info->bandwidth->intra[k]->value;
							scion_map_put(intra_bandwidth, &pb_static_info->bandwidth->intra[k]->key, bandwidth);
						}

						struct scion_map *inter_bandwidth = scion_map_create(
							(struct scion_map_key_config){ .size = INTERFACE_KEY_SIZE, .serialize = NULL },
							SCION_MAP_SIMPLE_FREE);

						for (size_t k = 0; k < pb_static_info->bandwidth->n_inter; k++) {
							uint64_t *bandwidth = malloc(sizeof(*bandwidth));
							*bandwidth = pb_static_info->bandwidth->inter[k]->value;
							scion_map_put(inter_bandwidth, &pb_static_info->bandwidth->inter[k]->key, bandwidth);
						}

						curr_as_entry->extensions.static_info->bandwidth = malloc(
							sizeof(*curr_as_entry->extensions.static_info->bandwidth));
						curr_as_entry->extensions.static_info->bandwidth->intra = intra_bandwidth;
						curr_as_entry->extensions.static_info->bandwidth->inter = inter_bandwidth;
					}

					if (pb_static_info->geo != NULL) {
						struct scion_map *geo = scion_map_create(
							(struct scion_map_key_config){ .size = INTERFACE_KEY_SIZE, .serialize = NULL },
							SCION_MAP_CUSTOM_FREE(scion_geo_coordinates_free));
						for (size_t k = 0; k < pb_static_info->n_geo; k++) {
							struct scion_geo_coordinates *curr_geo = malloc(sizeof(*curr_geo));
							curr_geo->latitude = pb_static_info->geo[k]->value->latitude;
							curr_geo->longitude = pb_static_info->geo[k]->value->longitude;

							char *address = pb_static_info->geo[k]->value->address;
							curr_geo->address = address == NULL ? NULL : strdup(address);

							scion_map_put(geo, &pb_static_info->geo[k]->key, curr_geo);
						}

						curr_as_entry->extensions.static_info->geo = geo;
					}

					if (pb_static_info->link_type != NULL) {
						struct scion_map *link_type = scion_map_create(
							(struct scion_map_key_config){ .size = INTERFACE_KEY_SIZE, .serialize = NULL },
							SCION_MAP_SIMPLE_FREE);
						for (size_t k = 0; k < pb_static_info->n_link_type; k++) {
							enum scion_link_type *curr_link_type = malloc(sizeof(*curr_link_type));
							*curr_link_type = (enum scion_link_type)pb_static_info->link_type[k]->value;

							scion_map_put(link_type, &pb_static_info->link_type[k]->key, curr_link_type);
						}

						curr_as_entry->extensions.static_info->link_type = link_type;
					}

					if (pb_static_info->internal_hops != NULL) {
						struct scion_map *internal_hops = scion_map_create(
							(struct scion_map_key_config){ .size = INTERFACE_KEY_SIZE, .serialize = NULL },
							SCION_MAP_SIMPLE_FREE);
						for (size_t k = 0; k < pb_static_info->n_internal_hops; k++) {
							uint32_t *curr_internal_hops = malloc(sizeof(*curr_internal_hops));
							*curr_internal_hops = pb_static_info->internal_hops[k]->value;

							scion_map_put(internal_hops, &pb_static_info->internal_hops[k]->key, curr_internal_hops);
						}

						curr_as_entry->extensions.static_info->internal_hops = internal_hops;
					}

					if (pb_static_info->note != NULL) {
						curr_as_entry->extensions.static_info->note = strdup(pb_static_info->note);
					}
				}
			}

			proto__crypto__v1__header_and_body_internal__free_unpacked(hb, NULL);
			proto__control_plane__v1__asentry_signed_body__free_unpacked(pb_as_entry, NULL);
		}
	}

	chain_cache_free_members(&cache);
	return ret;
}

/*
 *  Looks up the path segments required to build a path between a given source AS and destination AS
 *  by making the required gRPC calls to a SCION control server. If the network has TRCs, the segments that cannot be
 *  verified against them are left out.
 *
 * Arguments:
 * 		- const struct scion_network *net: The network, with the control server and the TRCs.
 * 		- ScionIA src: source AS.
 *      - ScionIA dst: destination AS.
 * 		- struct scion_path_segment_list *segments: Pointer to the scion_path_segment_list struct into which the result
 * will be saved.
 *
 * Returns:
 *      - An integer status code, 0 for success or an error code as defined in error.h.
 */
int scion_path_segments_lookup(
	const struct scion_network *net, scion_ia src, scion_ia dst, struct scion_path_segment_list *segments)
{
	assert(net);
	assert(segments);

	const struct scion_topology *topology = net->topology;
	int ret;

	// Initialize segments
	segments->list = NULL;
	segments->length = 0;
	segments->type = UNSPECIFIED_SEGMENT;

	Proto__ControlPlane__V1__SegmentsRequest seg_req = PROTO__CONTROL_PLANE__V1__SEGMENTS_REQUEST__INIT;
	u_int8_t *msg_buf;
	size_t len;

	seg_req.src_isd_as = src;
	seg_req.dst_isd_as = dst;

	len = proto__control_plane__v1__segments_request__get_packed_size(&seg_req);
	msg_buf = malloc(len);
	(void)proto__control_plane__v1__segments_request__pack(&seg_req, msg_buf);

	http2_rpc_handle hd;
	ret = http2_rpc_handle_init(
		&hd, (struct sockaddr *)&topology->cs_addr, topology->cs_addr_len, INITIAL_RPC_OUTPUT_BUFFER_SIZE);
	if (ret != 0) {
		goto cleanup_msg_buf;
	}

	ret = http2_rpc_request(&hd, SEGMENTS_PATH, msg_buf, len);
	if (ret != 0) {
		goto cleanup_rpc_handle;
	}

	if (hd.grpc_status_code != 0) {
		ret = http2_rpc_grpc_status_to_error(hd.grpc_status_code);
		goto cleanup_rpc_handle;
	}

	Proto__ControlPlane__V1__SegmentsResponse *response = proto__control_plane__v1__segments_response__unpack(
		NULL, hd.bytes_written, (const uint8_t *)hd.output_buffer);
	if (response == NULL) {
		ret = SCION_ERR_CONTROL_SERVICE_RESPONSE_INVALID;
		goto cleanup_rpc_handle;
	}

	if (response->n_segments > 0) {
		ret = protobuf_to_path_segments(net, response, segments);
	}
	proto__control_plane__v1__segments_response__free_unpacked(response, NULL);

cleanup_rpc_handle:
	http2_rpc_handle_free(&hd);

cleanup_msg_buf:
	free(msg_buf);

	return ret;
}

/*
 *  Frees the internal members provided scion_path_segment_list, including the scion_path_segment structs.
 *
 * Arguments:
 * 		- struct scion_path_segment_list *pathseg_list: Pointer to a scion_path_segment_list struct.
 */
void scion_free_pathseglist_internal(struct scion_path_segment_list *pathseg_list)
{
	if (pathseg_list == NULL) {
		return;
	}
	if (pathseg_list->list != NULL) {
		for (uint16_t i = 0; i < pathseg_list->length; i++) {
			scion_path_segment_free(pathseg_list->list[i]);
		}
		free(pathseg_list->list);
	}
}

/*
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
int scion_dst_core_check(const struct scion_topology *topology, scion_ia src, scion_ia dst)
{
	assert(topology);
	int ret;

	bool single_isd = (scion_ia_get_isd(src) == scion_ia_get_isd(dst));

	Proto__ControlPlane__V1__SegmentsRequest seg_req = PROTO__CONTROL_PLANE__V1__SEGMENTS_REQUEST__INIT;
	u_int8_t *msg_buf;
	size_t len;

	seg_req.src_isd_as = scion_ia_to_wildcard(src);
	seg_req.dst_isd_as = dst;

	len = proto__control_plane__v1__segments_request__get_packed_size(&seg_req);
	msg_buf = malloc(len);
	(void)proto__control_plane__v1__segments_request__pack(&seg_req, msg_buf);

	http2_rpc_handle hd;
	ret = http2_rpc_handle_init(
		&hd, (struct sockaddr *)&topology->cs_addr, topology->cs_addr_len, INITIAL_RPC_OUTPUT_BUFFER_SIZE);
	if (ret != 0) {
		free(msg_buf);
		return ret;
	}

	ret = http2_rpc_request(&hd, SEGMENTS_PATH, msg_buf, len);
	if (ret != 0) {
		free(msg_buf);
		http2_rpc_handle_free(&hd);
		return ret;
	}

	if (single_isd) {
		if (hd.grpc_status_code == 0) {
			Proto__ControlPlane__V1__SegmentsResponse *response = proto__control_plane__v1__segments_response__unpack(
				NULL, hd.bytes_written, (const uint8_t *)hd.output_buffer);
			if (response == NULL) {
				ret = SCION_ERR_CONTROL_SERVICE_RESPONSE_INVALID;
			} else if (response->n_segments > 0) {
				int32_t seg_type = response->segments[0]->key;
				if (seg_type == 3) {
					// segment type 3 == Core segment
					ret = 1;
				} else {
					ret = 0;
				}
			} else {
				// TODO: check this again
				// if it succeeds, i.e. status code 0, but has no segments, it has to be core.
				// Non-core always needs at least one segment otherwise it's disconnected. Which can't be.
				ret = 1;
			}
			proto__control_plane__v1__segments_response__free_unpacked(response, NULL);
		} else {
			ret = http2_rpc_grpc_status_to_error(hd.grpc_status_code);
		}
	} else {
		if (hd.grpc_status_code == 0) {
			ret = 1;
		} else if (hd.grpc_status_code == 2) {
			ret = 0;
		} else {
			ret = http2_rpc_grpc_status_to_error(hd.grpc_status_code);
		}
	}

	free(msg_buf);
	http2_rpc_handle_free(&hd);
	return ret;
}

size_t scion_pathsegment_list_byte_size(struct scion_path_segment_list *pathseglist)
{
	size_t size = 0;

	if (pathseglist != NULL) {
		size += sizeof(*pathseglist);
		size += pathseglist->length * sizeof(struct scion_path_segment *);
		for (uint16_t i = 0; i < pathseglist->length; i++) {
			size += scion_path_segment_byte_size(pathseglist->list[i]);
		}
	}

	return size;
}
