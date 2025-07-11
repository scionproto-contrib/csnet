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

#include <arpa/inet.h>
#include <stdbool.h>
#include <sys/socket.h>

#include "common/isd_as.h"
#include "control_plane/path_metadata.h"
#include "data_plane/underlay.h"
#include "scion/scion.h"
#include "util/list.h"

#define SCION_MAX_INFS 3
#define SCION_MAX_HOPS 64
#define SCION_META_LEN 4

enum scion_path_type { SCION_PATH_TYPE_EMPTY = 0, SCION_PATH_TYPE_SCION = 1 };

struct scion_path_raw {
	uint16_t length;
	uint8_t *raw;
};

struct scion_path {
	scion_ia src;
	scion_ia dst;
	struct scion_underlay underlay_next_hop;
	enum scion_path_type path_type;
	struct scion_path_raw *raw_path;
	struct scion_path_metadata *metadata;
	uint32_t weight;
};

struct scion_path_meta_hdr {
	uint8_t curr_inf;
	uint8_t curr_hf;
	uint8_t seg_len[3];
};

/*
 * FUNCTION: scion_path_meta_hdr_init
 * -------------------
 * Zero-initializes all members of a scion_path_meta_hdr struct.
 *
 * Arguments:
 *      - scion_path_meta_hdr* hdr: Pointer to the meta header which will be initialized.
 * Returns:
 *      - An integer status code, 0 for success or an error code as defined in error.h.
 */
int scion_path_meta_hdr_init(struct scion_path_meta_hdr *hdr);

/*
 * FUNCTION: scion_path_raw_init
 * -------------------
 * Initializes a scion_path_raw using the provided scion_path_meta_hdr, info fields and hop fields.
 *
 * Arguments:
 * 		- struct scion_path_raw *raw_path: Pointer to the scion_path_raw struct that will be initalized.
 *      - scion_path_meta_hdr* hdr: Pointer to the meta header.
 * 		- struct scion_linked_list *info_fields: Pointer to a scion_linked_list containing scion_info_field structs.
 * 		- struct scion_linked_list *hop_fields: Pointer to a scion_linked_list containing scion_hop_field structs.
 * Returns:
 *      - An integer status code, 0 for success or an error code as defined in error.h.
 */
int scion_path_raw_init(struct scion_path_raw *raw_path, struct scion_path_meta_hdr *hdr,
	struct scion_list *info_fields, struct scion_list *hop_fields);

/*
 * FUNCTION: scion_path_raw_free
 * -------------------
 * Frees a scion_path_raw struct.
 *
 * Arguments:
 *      - struct scion_path_raw *raw_path: Pointer to the raw path to be free'd.
 */
void scion_path_raw_free(struct scion_path_raw *raw_path);

/*
 * FUNCTION: scion_path_metadata_free
 * -------------------
 * Frees a scion_path_metadata struct.
 *
 * Arguments:
 *      - struct scion_path_metadata *path_meta: Pointer to the path metadata to be free'd.
 */
void scion_path_metadata_free(struct scion_path_metadata *path_meta);

/*
 * FUNCTION: scion_path_free
 * -------------------
 * Frees a scion_path struct.
 *
 * Arguments:
 *      - struct scion_path *path: Pointer to the scion_path struct to be free'd.
 */
void scion_path_free(struct scion_path *path);

/*
 * FUNCTION: scion_path_raw_reverse
 * -------------------
 * Reverses a scion_path_raw. Used to respond to a packet received from a source where no
 * previous path is available. This is done to use the same path as specified by the sender
 * and to avoid making requests to a control server.
 *
 * Arguments:
 * 		- struct scion_path_raw *path: Pointer to the scion_path_raw to be reversed.
 * Returns:
 *      - An integer status code, 0 for success or an error code as defined in error.h.
 */
int scion_path_raw_reverse(struct scion_path_raw *path);

void scion_path_print_interfaces(struct scion_path_interface *interfaces, size_t interfaces_len);

/*
 * FUNCTION: scion_path_print
 * -------------------
 * Prints a path, i.e. the hops (ASes and interfaces) and metadata.
 * Example: "Hops: [1ff0000000111 41>1 1ff0000000110 3>51 1ff0000000112] MTU: 1280\n"
 * Important: ADDS newline character at the end.
 *
 * Arguments:
 *      - const struct scion_path *path: Pointer to the scion_path.
 */
void scion_path_print(const struct scion_path *path);

uint32_t scion_path_byte_size(struct scion_path *path, bool print_details);

int scion_path_reverse(struct scion_path *path);

size_t scion_path_get_numhops(const struct scion_path *path);

/*
 * FUNCTION: scion_path_serialize
 * -----------------
 * Serializes a SCION path (which represented by a scion_path_meta_hdr struct, a scion_linked_list containing
 * scion_info_field structs and a scion_linked_list containing scion_hop_field structs) into a buffer.
 *
 * Arguments:
 *      - uint8_t *buf: Pointer to the buffer in which the serialized scion_udp struct will be saved.
 * 		- struct scion_path_meta_hdr *hdr: Pointer to the scion_path_meta_hdr struct which represents the Meta header to
 * be serialized.
 * 		- struct scion_linked_list *info_fields: scion_linked_list containing the scion_info_field structs to be
 * serialized.
 * 		- struct scion_linked_list *hop_fields: scion_linked_list containing the scion_hop_field structs to be
 * serialized.
 *
 * Returns:
 *      - A uint16_t status code:
 * 			if >= 0: the length of the serialized SCION path.
 * 			if < an error code as defined in error.h.
 */
int scion_path_serialize(
	struct scion_path_meta_hdr *hdr, struct scion_list *info_fields, struct scion_list *hop_fields, uint8_t *buf);

int scion_path_meta_hdr_serialize(struct scion_path_meta_hdr *hdr, uint8_t *buf);

/*
 * FUNCTION: scion_path_deserialize
 * -------------------
 * Takes a buffer which contains a serialized SCION path and deserializes it into a scion_path_meta_hdr struct,
 * a scion_linked_list containing scion_info_field structs and a scion_linked_list containing scion_hop_field structs.
 * IMPORTANT: the scion_path_meta_hdr struct needs to be allocated and both ScionLinkedLists need to be created
 * before calling this function.
 *
 * Arguments:
 *      - uint8_t *buf: Pointer to the buffer.
 * 		- struct scion_path_meta_hdr *hdr: Pointer to the scion_path_meta_hdr struct into which the Meta header will be
 * deserialized.
 * 		- struct scion_linked_list *info_fields: scion_linked_list into which the list of info fields will be
 * deserialized.
 * 		- struct scion_linked_list *hop_fields: scion_linked_list into which the list of hop fields will be
 * deserialized.
 *
 * Returns:
 *      - An integer status code, 0 for success or an error code as defined in error.h.
 */
int scion_path_deserialize(
	uint8_t *buf, struct scion_path_meta_hdr *hdr, struct scion_list *info_fields, struct scion_list *hop_fields);

int scion_path_meta_hdr_deserialize(const uint8_t *buf, struct scion_path_meta_hdr *hdr);

const struct scion_path_metadata *scion_path_get_metadata(const struct scion_path *path);

void scion_path_print_metadata(const struct scion_path *path);
