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

#pragma once

#include <stdbool.h>
#include <stdint.h>

#define SCION_SCMP_HDR_LEN 4
#define SCION_SCMP_ECHO_HDR_LEN (SCION_SCMP_HDR_LEN + 4)

typedef enum scion_scmp_echo_type { SCION_ECHO_TYPE_REQUEST = 128, SCION_ECHO_TYPE_REPLY = 129 } scion_scmp_echo_type_t;

struct scion_scmp_echo {
	scion_scmp_echo_type_t type;
	uint16_t id;
	uint16_t seqno;
	uint8_t *data;
	uint16_t data_length;
};

uint8_t scion_scmp_get_type(const uint8_t *buf, uint16_t buf_len);

uint8_t scion_scmp_get_code(const uint8_t *buf, uint16_t buf_len);

bool scion_scmp_is_error(const uint8_t *buf, uint16_t buf_len);

int scion_scmp_echo_deserialize(const uint8_t *buf, uint16_t buf_len, struct scion_scmp_echo *scion_scmp_echo);

int scion_scmp_echo_serialize(const struct scion_scmp_echo *scion_scmp_echo, uint8_t *buf, uint16_t buf_len);

void scion_scmp_echo_free_internal(struct scion_scmp_echo *scion_scmp_echo);
