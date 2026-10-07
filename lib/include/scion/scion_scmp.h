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

/**
 * @file scion_scmp.h
 *
 * The SCMP API of the csnet library.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include <scion/scion.h>

/**
 * Gets the type of a SCMP message.
 * @param[in] buf The serialized SCMP message.
 * @param[in] buf_len The length of the SCMP message.
 * @return The type of the SCMP message.
 *
 * @see https://docs.scion.org/en/latest/protocols/scmp.html#types
 */
uint8_t scion_scmp_get_type(const uint8_t *buf, uint16_t buf_len);

/**
 * Gets the code of a SCMP message.
 * @param[in] buf The serialized SCMP messsage.
 * @param[in] buf_len The length of the SCMP message.
 * @return The code of the SCMP message.
 */
uint8_t scion_scmp_get_code(const uint8_t *buf, uint16_t buf_len);

/**
 * Determines whether the SCMP message is an error message.
 * @param[in] buf The serialized SCMP message.
 * @param[in] buf_len The length of the serialized SCMP message.
 * @return true if the SCMP message is an error message, false otherwise.
 *
 * @see https://docs.scion.org/en/latest/protocols/scmp.html#types
 */
bool scion_scmp_is_error(const uint8_t *buf, uint16_t buf_len);

/**
 * The SCMP echo message types.
 */
enum scion_scmp_echo_type {
	/**
	 * An echo request.
	 *
	 * @see https://docs.scion.org/en/latest/protocols/scmp.html#echo-request
	 */
	SCION_ECHO_TYPE_REQUEST = 128,
	/**
	 * An echo reply.
	 *
	 * @see https://docs.scion.org/en/latest/protocols/scmp.html#echo-reply
	 */
	SCION_ECHO_TYPE_REPLY = 129
};

/**
 * An SCMP echo message.
 */
struct scion_scmp_echo {
	/** the type */
	enum scion_scmp_echo_type type;
	/** the identifier */
	uint16_t id;
	/** the sequence number */
	uint16_t seqno;
	/** the data */
	uint8_t *data;
	/** the length of the data */
	uint16_t data_length;
};

/**
 * Determines how large the serialized SCMP echo message will be.
 * @param[in] scmp_echo The SCMP echo message.
 * @return the size of the serialized SCMP echo message in bytes.
 */
uint16_t scion_scmp_echo_len(struct scion_scmp_echo *scmp_echo);

/**
 * Serializes an SCMP echo message.
 * @param[in] scmp_echo The SCMP echo message to serialize.
 * @param[out] buf The serialized SCMP echo message.
 * @param[in] buf_len The length of the serialized message.
 * @return 0 on success, a negative error code on failure.
 *
 * @note Use @link scion_scmp_echo_len @endlink to determine how large the buffer needs to be.
 */
int scion_scmp_echo_serialize(const struct scion_scmp_echo *scmp_echo, uint8_t *buf, uint16_t buf_len);

/**
 * Deserializes an SCMP echo message.
 * @param[in] buf The serialized SCMP echo message.
 * @param[in] buf_len The length of the serialized message.
 * @param[out] scmp_echo The SCMP echo message.
 * @return 0 on success, a negative error code on failure.
 */
int scion_scmp_echo_deserialize(const uint8_t *buf, uint16_t buf_len, struct scion_scmp_echo *scmp_echo);

/**
 * Frees the intrenal memebers of a SCMP echo message.
 * @param[in] scmp_echo The SCMP echo message.
 */
void scion_scmp_echo_free_members(struct scion_scmp_echo *scmp_echo);

/**
 * A callback for SCMP error handling.
 * @param buf The buffer containing the SCMP error message.
 * @param size The size of the buffer.
 * @param ctx The context that was provided when setting up the callback.
 *
 * @see @link scion_setsockerrcb @endlink
 */
typedef void scion_socket_scmp_error_cb(uint8_t *buf, size_t size, void *ctx);

/**
 * Sets the SCMP error callback that is called when a SCMP error is received by the socket.
 * @param[in,out] scion_sock The socket.
 * @param[in] cb The callback to use.
 * @param[in] ctx The user-defined context that is passed to every invocation of the callback. Can be NULL.
 * @return 0 on success, a negative error code on failure.
 */
int scion_setsockerrcb(struct scion_socket *scion_sock, scion_socket_scmp_error_cb cb, void *ctx);

#ifdef __cplusplus
}
#endif
