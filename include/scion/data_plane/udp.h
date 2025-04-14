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

#include <endian.h>
#include <stdint.h>

#define SCION_UDP_HDR_LEN 8

struct scion_udp {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t data_length;
	uint8_t *data;
};

/*
 * FUNCTION: scion_udp_free_internal
 * -------------------
 * Frees, if applicable, and set all internal values to 0 or NULL of a scion_udp struct, without freeing the struct
 * itself.
 *
 * Arguments:
 *      - struct scion_udp *udp: Pointer to the udp packet.
 */
void scion_udp_free_internal(struct scion_udp *udp);

/*
 * FUNCTION: scion_udp_free
 * -------------------
 * Frees a scion_udp struct.
 *
 * Arguments:
 *      - struct scion_udp *udp: Pointer to the udp packet.
 */
void scion_udp_free(struct scion_udp *udp);

uint16_t scion_udp_len(struct scion_udp *udp);

/*
 * FUNCTION: scion_udp_serialize
 * -----------------
 * Serializes a scion_udp struct (which represents the internal UDP packet that is sent via SCION).
 *
 * Arguments:
 *      - uint8_t *buf: Pointer to the buffer in which the serialized scion_udp struct will be saved.
 *      - struct scion_udp *udp: Pointer to the scion_udp struct.
 *
 * Returns:
 *      - A uint16_t status code:
 * 			if >= 0: the length of the serialized scion_udp struct.
 * 			if < an error code as defined in error.h.
 */
int scion_udp_serialize(struct scion_udp *udp, uint8_t *buf, uint16_t *len);

/*
 * FUNCTION: scion_udp_deserialize
 * -------------------
 * Takes a buffer which contains a serialized UDP packet and deserializes it into a scion_udp struct.
 * IMPORTANT: the scion_udp struct need to be allocated before calling this function.
 *
 * Arguments:
 *      - struct scion_udp *udp: scion_udp struct into which the UDP packet will be deserialized.
 *      - uint8_t *buf: Pointer to the buffer.
 *      - int buf_len: length of the provided buffer.
 *
 * Returns:
 *      - An integer status code, 0 for success or an error code as defined in error.h.
 */
int scion_udp_deserialize(uint8_t *buf, uint16_t len, struct scion_udp *udp);
