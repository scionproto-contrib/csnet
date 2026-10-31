// Copyright 2026 ETH Zurich
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

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "scion/scion_scmp.h"

/*
 * Returns the type of an SCMP message, 0 if the buffer is too short. A type that is not defined by the SCMP
 * specification is returned as it is.
 */
enum scion_scmp_type scion_scmp_get_type(const uint8_t *buf, uint16_t buf_len);

/*
 * Returns the code of an SCMP message, 0 if the buffer is too short.
 */
uint8_t scion_scmp_get_code(const uint8_t *buf, uint16_t buf_len);

/*
 * Returns whether an SCMP message is an error message.
 */
bool scion_scmp_is_error(const uint8_t *buf, uint16_t buf_len);

/*
 * Returns the name of an SCMP message type, "unknown" if it is not defined by the SCMP specification.
 */
const char *scion_scmp_type_str(enum scion_scmp_type type);

/*
 * Returns the description of an SCMP message code, "none" for code 0 of a type without codes, or "unknown" if the code
 * is not defined by the SCMP specification for the type.
 */
const char *scion_scmp_code_str(enum scion_scmp_type type, uint8_t code);

/*
 * Returns the size of the serialized SCMP error message in bytes, or 0 if the type is not a known SCMP error type.
 */
size_t scion_scmp_error_len(const struct scion_scmp_error *scmp_error);

/*
 * Serializes an SCMP error message, without the checksum, into a buffer of at least scion_scmp_error_len bytes.
 */
int scion_scmp_error_serialize(const struct scion_scmp_error *scmp_error, uint8_t *buf, size_t buf_len);

/*
 * Deserializes an SCMP error message. The quoted packet is copied into memory that is freed with
 * scion_scmp_error_free_members. Returns SCION_ERR_PACKET_FIELD_INVALID if the type is not a known SCMP error type.
 * The code and the checksum are not validated.
 */
int scion_scmp_error_deserialize(const uint8_t *buf, size_t buf_len, struct scion_scmp_error *scmp_error);

/*
 * Frees the quoted packet of an SCMP error message that was deserialized with scion_scmp_error_deserialize.
 */
void scion_scmp_error_free_members(struct scion_scmp_error *scmp_error);
