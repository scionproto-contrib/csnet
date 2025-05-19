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

#include "path_metadata.h"
#include "common/as_entry.h"
#include "data_plane/path.h"
#include "util/map.h"

#include <assert.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// TODO make key serialization function an argument when instantiating the map

static struct timeval latency_unset = { .tv_sec = 0, .tv_usec = -1 };
static uint64_t bandwidth_unset = 0;
static struct scion_geo_coordinates geo_unset = { .latitude = NAN, .longitude = NAN, .address = NULL };
static enum scion_link_type link_type_unset = SCION_LINK_TYPE_UNSPECIFIED;
static uint32_t internal_hops_unset = 0;

struct hop_key {
	struct scion_path_interface *a;
	struct scion_path_interface *b;
};

#define HOP_KEY_SIZE 32
static void serialize_hop_key(struct hop_key *hop_key, void *buffer)
{
	uint64_t *key = buffer;

	if (hop_key->a->ia > hop_key->b->ia || (hop_key->a->ia == hop_key->b->ia && hop_key->a->id > hop_key->b->id)) {
		key[0] = hop_key->b->ia;
		key[1] = hop_key->b->id;
		key[2] = hop_key->a->ia;
		key[3] = hop_key->a->id;
		return;
	}

	key[0] = hop_key->a->ia;
	key[1] = hop_key->a->id;
	key[2] = hop_key->b->ia;
	key[3] = hop_key->b->id;
}

#define INTERFACE_KEY_SIZE 16
static void serialize_interface_key(struct scion_path_interface *interface, void *buffer)
{
	uint64_t *key = buffer;
	key[0] = interface->ia;
	key[1] = interface->id;
}

#define IA_KEY_SIZE 8

void scion_geo_coordinates_free(struct scion_geo_coordinates *geo)
{
	if (geo == NULL) {
		return;
	}

	free(geo->address);
	free(geo);
}

void scion_path_metadata_free(struct scion_path_metadata *path_meta)
{
	if (path_meta == NULL) {
		return;
	}

	size_t num_interfaces = scion_list_size(path_meta->interfaces);
	scion_list_free(path_meta->interfaces);

	size_t num_as = scion_list_size(path_meta->as_numbers);
	scion_list_free(path_meta->as_numbers);

	free(path_meta->latencies);
	free(path_meta->bandwidths);

	if (path_meta->geo) {
		for (size_t i = 0; i < num_interfaces; i++) {
			free(path_meta->geo[i].address);
		}

		free(path_meta->geo);
	}

	free(path_meta->link_types);
	free(path_meta->internal_hops);

	if (path_meta->notes) {
		for (size_t i = 0; i < num_as; i++) {
			free(path_meta->notes[i]);
		}
		free(path_meta->notes);
	}

	free(path_meta);
}

static struct scion_linked_list *collect_as_numbers(struct scion_linked_list *interfaces)
{
	struct scion_linked_list *as_numbers = scion_list_create(SCION_LIST_SIMPLE_FREE);
	struct scion_linked_list_node *current = interfaces->first;

	while (current) {
		scion_ia *as_number = malloc(sizeof(*as_number));
		*as_number = ((struct scion_path_interface *)current->value)->ia;
		scion_list_append(as_numbers, as_number);

		if (current == interfaces->first) {
			current = current->next;
		} else if (current->next != NULL) {
			current = current->next->next;
		} else {
			current = NULL;
		}
	}

	return as_numbers;
}

static void add_hop_latency(
	struct scion_map *map, struct scion_path_interface *a, struct scion_path_interface *b, struct timeval *latency)
{
	if (latency == NULL) {
		return;
	}

	struct hop_key key = { a, b };
	struct timeval *current = scion_map_get(map, &key);

	if (current == NULL || timercmp(current, latency, <)) {
		scion_map_put(map, &key, latency);
	}
}

static struct timeval *collect_latencies(
	struct scion_linked_list *interfaces, struct scion_linked_list *as_entries, struct scion_map *remote_interfaces)
{
	struct scion_map *hop_latencies = scion_map_create(
		(struct scion_map_key_config){ .size = HOP_KEY_SIZE, .serialize = (scion_map_serialize_key)serialize_hop_key },
		SCION_MAP_NO_FREE_VALUES);

	struct scion_linked_list_node *current = as_entries->first;
	while (current) {
		struct scion_as_entry *as_entry = current->value;

		struct scion_path_interface egress_interface = { .ia = as_entry->local,
			.id = as_entry->hop_entry.hop_field.cons_egress };

		if (as_entry->extensions.static_info != NULL && as_entry->extensions.static_info->latency != NULL) {
			// Egress to sibling child, core or peer interfaces
			struct scion_linked_list_node *current_key_value
				= as_entry->extensions.static_info->latency->intra->key_value_pairs->first;

			while (current_key_value) {
				struct scion_map_key_value_pair *kvp = current_key_value->value;
				struct scion_path_interface other_interface = { .ia = as_entry->local, .id = *(uint16_t *)kvp->key };

				add_hop_latency(hop_latencies, &egress_interface, &other_interface, kvp->value);

				current_key_value = current_key_value->next;
			}

			// Local peer to remote peer interface
			current_key_value = as_entry->extensions.static_info->latency->inter->key_value_pairs->first;

			while (current_key_value) {
				struct scion_map_key_value_pair *kvp = current_key_value->value;
				struct scion_path_interface local_interface = { .ia = as_entry->local, .id = *(uint16_t *)kvp->key };

				struct scion_path_interface *remote_if = scion_map_get(remote_interfaces, &local_interface);

				if (remote_if != NULL) {
					add_hop_latency(hop_latencies, &local_interface, remote_if, kvp->value);
				}

				current_key_value = current_key_value->next;
			}
		}

		current = current->next;
	}

	size_t latencies_size = scion_list_size(interfaces) - 1;
	struct timeval *latencies = calloc(latencies_size, sizeof(*latencies));
	for (size_t i = 0; i < latencies_size; i++) {
		struct hop_key key = { .a = scion_list_get(interfaces, i), .b = scion_list_get(interfaces, i + 1) };
		struct timeval *latency = scion_map_get(hop_latencies, &key);

		if (latency != NULL) {
			latencies[i] = *latency;
		} else {
			latencies[i] = latency_unset;
		}
	}

	scion_map_free(hop_latencies);

	return latencies;
}

static void add_hop_bandwidth(
	struct scion_map *map, struct scion_path_interface *a, struct scion_path_interface *b, uint64_t *bandwidth)
{
	if (bandwidth == NULL) {
		return;
	}

	struct hop_key key = { a, b };
	uint64_t *current = scion_map_get(map, &key);

	if (current == NULL || *current < *bandwidth) {
		scion_map_put(map, &key, bandwidth);
	}
}

static uint64_t *collect_bandwidths(
	struct scion_linked_list *interfaces, struct scion_linked_list *as_entries, struct scion_map *remote_interfaces)
{
	struct scion_map *hop_bandwidths = scion_map_create(
		(struct scion_map_key_config){ .size = HOP_KEY_SIZE, .serialize = (scion_map_serialize_key)serialize_hop_key },
		SCION_MAP_NO_FREE_VALUES);

	struct scion_linked_list_node *current = as_entries->first;
	while (current) {
		struct scion_as_entry *as_entry = current->value;

		struct scion_path_interface egress_interface = { .ia = as_entry->local,
			.id = as_entry->hop_entry.hop_field.cons_egress };

		if (as_entry->extensions.static_info != NULL && as_entry->extensions.static_info->bandwidth != NULL) {
			// Egress to sibling child, core or peer interfaces
			struct scion_linked_list_node *current_key_value
				= as_entry->extensions.static_info->bandwidth->intra->key_value_pairs->first;

			while (current_key_value) {
				struct scion_map_key_value_pair *kvp = current_key_value->value;
				struct scion_path_interface other_interface = { .ia = as_entry->local, .id = *(uint16_t *)kvp->key };

				add_hop_bandwidth(hop_bandwidths, &egress_interface, &other_interface, kvp->value);

				current_key_value = current_key_value->next;
			}

			// Local peer to remote peer interface
			current_key_value = as_entry->extensions.static_info->bandwidth->inter->key_value_pairs->first;

			while (current_key_value) {
				struct scion_map_key_value_pair *kvp = current_key_value->value;
				struct scion_path_interface local_interface = { .ia = as_entry->local, .id = *(uint16_t *)kvp->key };

				struct scion_path_interface *remote_if = scion_map_get(remote_interfaces, &local_interface);

				if (remote_if != NULL) {
					add_hop_bandwidth(hop_bandwidths, &local_interface, remote_if, kvp->value);
				}

				current_key_value = current_key_value->next;
			}
		}

		current = current->next;
	}

	size_t bandwidths_size = scion_list_size(interfaces) - 1;
	uint64_t *bandwidths = calloc(bandwidths_size, sizeof(*bandwidths));
	for (size_t i = 0; i < bandwidths_size; i++) {
		struct hop_key key = { scion_list_get(interfaces, i), scion_list_get(interfaces, i + 1) };
		uint64_t *bandwidth = scion_map_get(hop_bandwidths, &key);

		if (bandwidth != NULL) {
			bandwidths[i] = *bandwidth;
		} else {
			bandwidths[i] = bandwidth_unset;
		}
	}

	scion_map_free(hop_bandwidths);

	return bandwidths;
}

struct scion_geo_coordinates *collect_geo_coordinates(
	struct scion_linked_list *interfaces, struct scion_linked_list *as_entries)
{
	struct scion_map *iface_geos = scion_map_create((struct scion_map_key_config){ .size = INTERFACE_KEY_SIZE,
														.serialize = (scion_map_serialize_key)serialize_interface_key },
		SCION_MAP_NO_FREE_VALUES);

	struct scion_linked_list_node *current = as_entries->first;
	while (current) {
		struct scion_as_entry *as_entry = current->value;

		if (as_entry->extensions.static_info != NULL && as_entry->extensions.static_info->geo != NULL) {
			struct scion_linked_list_node *current_key_value
				= as_entry->extensions.static_info->geo->key_value_pairs->first;

			while (current_key_value) {
				struct scion_map_key_value_pair *kvp = current_key_value->value;

				struct scion_path_interface interface = { .ia = as_entry->local,
					.id = *(scion_interface_id *)kvp->key };

				scion_map_put(iface_geos, &interface, kvp->value);

				current_key_value = current_key_value->next;
			}
		}

		current = current->next;
	}

	size_t geos_size = scion_list_size(interfaces);
	struct scion_geo_coordinates *geos = calloc(geos_size, sizeof(*geos));

	for (size_t i = 0; i < geos_size; i++) {
		struct scion_geo_coordinates *geo = scion_map_get(iface_geos, scion_list_get(interfaces, i));

		if (geo != NULL) {
			geos[i] = *geo;
			geos[i].address = strdup(geos[i].address);
		} else {
			geos[i] = geo_unset;
		}
	}

	scion_map_free(iface_geos);

	return geos;
}

enum scion_link_type *collect_link_types(
	struct scion_linked_list *interfaces, struct scion_linked_list *as_entries, struct scion_map *remote_interfaces)
{
	struct scion_map *hop_link_types = scion_map_create(
		(struct scion_map_key_config){ .size = HOP_KEY_SIZE, (scion_map_serialize_key)serialize_hop_key },
		SCION_MAP_NO_FREE_VALUES);

	struct scion_linked_list_node *current = as_entries->first;
	while (current) {
		struct scion_as_entry *as_entry = current->value;

		if (as_entry->extensions.static_info != NULL && as_entry->extensions.static_info->link_type != NULL) {
			struct scion_linked_list_node *current_key_value
				= as_entry->extensions.static_info->link_type->key_value_pairs->first;

			while (current_key_value) {
				struct scion_map_key_value_pair *kvp = current_key_value->value;
				struct scion_path_interface local_interface = { .ia = as_entry->local, .id = *(uint16_t *)kvp->key };

				struct scion_path_interface *remote_interface = scion_map_get(remote_interfaces, &local_interface);

				if (remote_interface != NULL) {
					struct hop_key key = { &local_interface, remote_interface };

					enum scion_link_type *previous = scion_map_get(hop_link_types, &key);

					if (previous != NULL) {
						// Handle conflicts by using link type unspecified
						if (*previous != *(enum scion_link_type *)kvp->value) {
							scion_map_put(hop_link_types, &key, &link_type_unset);
						}
					} else {
						scion_map_put(hop_link_types, &key, kvp->value);
					}
				}

				current_key_value = current_key_value->next;
			}
		}

		current = current->next;
	}

	size_t link_types_size = scion_list_size(interfaces) / 2;
	enum scion_link_type *link_types = calloc(link_types_size, sizeof(*link_types));
	for (size_t i = 0; i < link_types_size; i++) {
		struct hop_key key = { scion_list_get(interfaces, 2 * i), scion_list_get(interfaces, 2 * i + 1) };
		enum scion_link_type *link_type = scion_map_get(hop_link_types, &key);

		if (link_type != NULL) {
			link_types[i] = *link_type;
		} else {
			link_types[i] = SCION_LINK_TYPE_UNSPECIFIED;
		}
	}

	scion_map_free(hop_link_types);

	return link_types;
}

static void add_hop_internal_hops(
	struct scion_map *map, struct scion_path_interface *a, struct scion_path_interface *b, uint32_t *internal_hops)
{
	if (internal_hops == NULL) {
		return;
	}

	struct hop_key key = { a, b };
	uint32_t *current = scion_map_get(map, &key);

	if (current == NULL || *current < *internal_hops) {
		scion_map_put(map, &key, internal_hops);
	}
}

static uint32_t *collect_internal_hops(struct scion_linked_list *interfaces, struct scion_linked_list *as_entries)
{
	struct scion_map *hop_internal_hops = scion_map_create(
		(struct scion_map_key_config){ .size = HOP_KEY_SIZE, .serialize = (scion_map_serialize_key)serialize_hop_key },
		SCION_MAP_NO_FREE_VALUES);

	struct scion_linked_list_node *current = as_entries->first;
	while (current) {
		struct scion_as_entry *as_entry = current->value;

		struct scion_path_interface egress_interface = { .ia = as_entry->local,
			.id = as_entry->hop_entry.hop_field.cons_egress };

		if (as_entry->extensions.static_info != NULL && as_entry->extensions.static_info->internal_hops != NULL) {
			struct scion_linked_list_node *current_key_value
				= as_entry->extensions.static_info->internal_hops->key_value_pairs->first;

			while (current_key_value) {
				struct scion_map_key_value_pair *kvp = current_key_value->value;
				struct scion_path_interface other_interface = { .ia = as_entry->local, .id = *(uint16_t *)kvp->key };

				add_hop_internal_hops(hop_internal_hops, &egress_interface, &other_interface, kvp->value);

				current_key_value = current_key_value->next;
			}
		}

		current = current->next;
	}

	size_t internal_hops_size = (scion_list_size(interfaces) - 2) / 2;
	uint32_t *internal_hops = calloc(internal_hops_size, sizeof(*internal_hops));
	for (size_t i = 0; i < internal_hops_size; i++) {
		struct hop_key key = { scion_list_get(interfaces, 2 * i + 1), scion_list_get(interfaces, 2 * i + 2) };
		uint32_t *internal_hops_value = scion_map_get(hop_internal_hops, &key);

		if (internal_hops_value != NULL) {
			internal_hops[i] = *internal_hops_value;
		} else {
			internal_hops[i] = internal_hops_unset;
		}
	}

	scion_map_free(hop_internal_hops);

	return internal_hops;
}

static bool match_string(char *str, char *search_str)
{
	size_t str_len = strlen(str);
	size_t search_str_len = strlen(search_str);

	return strncmp(str, search_str, (str_len > search_str_len ? str_len : search_str_len) + 1) == 0;
}

char **collect_notes(struct scion_linked_list *as_entries, struct scion_linked_list *as_numbers)
{
	struct scion_map *as_notes = scion_map_create(
		(struct scion_map_key_config){ .size = IA_KEY_SIZE, .serialize = NULL },
		SCION_MAP_CUSTOM_FREE(scion_list_free));

	struct scion_linked_list_node *current = as_entries->first;
	while (current) {
		struct scion_as_entry *as_entry = current->value;

		if (as_entry->extensions.static_info != NULL && as_entry->extensions.static_info->note != NULL) {
			scion_ia ia = as_entry->local;

			struct scion_linked_list *notes = scion_map_get(as_notes, &ia);

			if (notes == NULL) {
				notes = scion_list_create(SCION_LIST_NO_FREE_VALUES);
				scion_map_put(as_notes, &ia, notes);
			}

			// only add non-duplicate string
			if (scion_list_find(notes, (struct scion_list_predicate){ .fn = (scion_list_predicate_fn)match_string,
										   .ctx = as_entry->extensions.static_info->note })
				== NULL) {
				scion_list_append(notes, as_entry->extensions.static_info->note);
			}
		}

		current = current->next;
	}

	size_t notes_size = scion_list_size(as_numbers);
	char **notes = calloc(notes_size, sizeof(*notes));

	for (size_t i = 0; i < notes_size; i++) {
		scion_ia *ia = scion_list_get(as_numbers, i);

		// allocate empty string
		notes[i] = calloc(1, sizeof(char));

		struct scion_linked_list *note_list = scion_map_get(as_notes, ia);

		if (note_list) {
			current = note_list->first;

			while (current) {
				size_t note_len = strlen(notes[i]);
				size_t note_to_add_len = strlen(current->value);

				if (note_len == 0) {
					notes[i] = realloc(notes[i], note_to_add_len + 1);
					(void)strncpy(notes[i], current->value, note_to_add_len + 1);
				} else {
					notes[i] = realloc(notes[i], note_len + strlen("\n") + note_to_add_len + 1);
					(void)strncat(notes[i], "\n", strlen("\n") + 1);
					(void)strncat(notes[i], current->value, note_to_add_len + 1);
				}

				current = current->next;
			}
		}
	}

	scion_map_free(as_notes);

	return notes;
}

struct scion_path_metadata *scion_path_metadata_collect(
	struct scion_linked_list *interfaces, struct scion_linked_list *as_entries, uint32_t mtu, int64_t expiry)
{
	assert(scion_list_size(interfaces) % 2 == 0);
	assert(scion_list_size(interfaces) > 0);

	struct scion_map *remote_interface = scion_map_create(
		(struct scion_map_key_config){ .size = INTERFACE_KEY_SIZE, (scion_map_serialize_key)serialize_interface_key },
		SCION_MAP_NO_FREE_VALUES);
	struct scion_linked_list_node *from = interfaces->first;
	struct scion_linked_list_node *to = from->next;

	while (from) {
		scion_map_put(remote_interface, from->value, to->value);
		scion_map_put(remote_interface, to->value, from->value);

		from = to->next;
		if (from != NULL) {
			to = from->next;
		}
	}

	struct scion_path_metadata *path_meta = calloc(1, sizeof(*path_meta));
	path_meta->interfaces = interfaces;
	path_meta->expiry = expiry;
	path_meta->mtu = mtu;
	path_meta->as_numbers = collect_as_numbers(interfaces);
	path_meta->latencies = collect_latencies(interfaces, as_entries, remote_interface);
	path_meta->bandwidths = collect_bandwidths(interfaces, as_entries, remote_interface);
	path_meta->geo = collect_geo_coordinates(interfaces, as_entries);
	path_meta->link_types = collect_link_types(interfaces, as_entries, remote_interface);
	path_meta->internal_hops = collect_internal_hops(interfaces, as_entries);
	path_meta->notes = collect_notes(as_entries, path_meta->as_numbers);

	scion_map_free(remote_interface);

	return path_meta;
}

void scion_path_metadata_print(struct scion_path_metadata *path_meta)
{
	if (path_meta == NULL) {
		(void)printf("No metadata available\n");
		return;
	}

	(void)printf("ASes:\n");
	struct scion_linked_list_node *current = path_meta->as_numbers->first;
	while (current) {
		scion_ia_print(*(scion_as *)current->value);
		(void)printf(", ");
		current = current->next;
	}
	(void)printf("\n");

	(void)printf("Interfaces:\n");
	current = path_meta->interfaces->first;
	while (current) {
		(void)printf("%" PRIu64 ", ", ((struct scion_path_interface *)current->value)->id);
		current = current->next;
	}
	(void)printf("\n");

	(void)printf("MTU: %" PRIu32 "\n", path_meta->mtu);

	struct tm *tm_info = localtime((time_t *)&path_meta->expiry);
	char expiry_str[20];
	if (strftime(expiry_str, sizeof(expiry_str), "%Y-%m-%d %H:%M:%S", tm_info) != 0) {
		(void)printf("Expiry: %s\n", expiry_str);
	}

	(void)printf("Latencies:\n");
	for (size_t i = 0; i < scion_list_size(path_meta->interfaces) - 1; i++) {
		struct timeval latency = path_meta->latencies[i];

		(void)printf(" %" PRIu64 " > %" PRIu64 ": ",
			((struct scion_path_interface *)scion_list_get(path_meta->interfaces, i))->id,
			((struct scion_path_interface *)scion_list_get(path_meta->interfaces, i + 1))->id);
		if (SCION_PATH_METADATA_LATENCY_IS_UNSET(latency)) {
			(void)printf("unknown");
		} else {
			(void)printf("%ld ms", (long int)(latency.tv_sec * 1000 + latency.tv_usec / 1000));
		}
		(void)printf("\n");
	}

	(void)printf("Bandwidths:\n");
	for (size_t i = 0; i < scion_list_size(path_meta->interfaces) - 1; i++) {
		uint64_t bandwidth = path_meta->bandwidths[i];

		(void)printf(" %" PRIu64 " > %" PRIu64 ": ",
			((struct scion_path_interface *)scion_list_get(path_meta->interfaces, i))->id,
			((struct scion_path_interface *)scion_list_get(path_meta->interfaces, i + 1))->id);
		if (SCION_PATH_METADATA_BANDWIDTH_IS_UNSET(bandwidth)) {
			(void)printf("unknown");
		} else {
			(void)printf("%" PRIu64 " kbit/s", bandwidth);
		}
		(void)printf("\n");
	}

	(void)printf("Geo:\n");
	for (size_t i = 0; i < scion_list_size(path_meta->interfaces); i++) {
		struct scion_geo_coordinates geo = path_meta->geo[i];

		(void)printf(" %zu: ", i);
		if (SCION_PATH_METADATA_GEO_IS_UNSET(geo)) {
			(void)printf("unknown");
		} else {
			(void)printf("%.5f,%.5f", geo.latitude, geo.longitude);
			if (geo.address != NULL) {
				(void)printf(" (%s)", geo.address);
			}
		}
		(void)printf("\n");
	}

	(void)printf("Link Types:\n");
	for (size_t i = 0; i < scion_list_size(path_meta->interfaces) / 2; i++) {
		enum scion_link_type link_type = path_meta->link_types[i];

		(void)printf(" %zu > %zu: ", 2 * i, 2 * i + 1);
		switch (link_type) {
		case SCION_LINK_TYPE_UNSPECIFIED:
			(void)printf("unknown");
			break;
		case SCION_LINK_TYPE_DIRECT:
			(void)printf("direct");
			break;
		case SCION_LINK_TYPE_MULTI_HOP:
			(void)printf("multihop");
			break;
		case SCION_LINK_TYPE_OPEN_NET:
			(void)printf("opennet");
			break;
		}
		(void)printf("\n");
	}

	(void)printf("Internal Hops:\n");
	for (size_t i = 0; i < (scion_list_size(path_meta->interfaces) - 2) / 2; i++) {
		uint32_t internal_hops = path_meta->internal_hops[i];
		struct scion_path_interface *interface = scion_list_get(path_meta->interfaces, 2 * i);

		(void)printf(" ");
		scion_ia_print(interface->ia);
		(void)printf(": ");

		if (SCION_PATH_METADATA_INTERNAL_HOPS_UNSET(internal_hops)) {
			(void)printf("unknown");
		} else {
			(void)printf("%" PRIu32, internal_hops);
		}

		(void)printf("\n");
	}

	(void)printf("Notes:\n");
	for (size_t i = 0; i < scion_list_size(path_meta->as_numbers); i++) {
		char *note = path_meta->notes[i];

		if (note != NULL && strlen(note) > 0) {
			(void)printf(" ");
			scion_ia_print(*(scion_as *)scion_list_get(path_meta->as_numbers, i));
			(void)printf(": ");

			(void)printf("\"%s\"", note);

			(void)printf("\n");
		}
	}
}
