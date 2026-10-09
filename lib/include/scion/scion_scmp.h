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
 * The SCMP message types.
 *
 * Types below 128 are error messages, types from 128 on are informational messages.
 *
 * @see https://docs.scion.org/en/latest/protocols/scmp.html#types
 */
enum scion_scmp_type {
	/** The packet could not be delivered to its destination. */
	SCION_SCMP_TYPE_DESTINATION_UNREACHABLE = 1,
	/** The packet is larger than the MTU of the next-hop link. */
	SCION_SCMP_TYPE_PACKET_TOO_BIG = 2,
	/** A header field of the packet is invalid. */
	SCION_SCMP_TYPE_PARAMETER_PROBLEM = 4,
	/** The link to an external AS is down. */
	SCION_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN = 5,
	/** The connectivity between two border routers of an AS is down. */
	SCION_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN = 6,
	/**
	 * An echo request.
	 *
	 * @see https://docs.scion.org/en/latest/protocols/scmp.html#echo-request
	 */
	SCION_SCMP_TYPE_ECHO_REQUEST = 128,
	/**
	 * An echo reply.
	 *
	 * @see https://docs.scion.org/en/latest/protocols/scmp.html#echo-reply
	 */
	SCION_SCMP_TYPE_ECHO_REPLY = 129,
	/**
	 * A traceroute request.
	 *
	 * @see https://docs.scion.org/en/latest/protocols/scmp.html#traceroute-request
	 */
	SCION_SCMP_TYPE_TRACEROUTE_REQUEST = 130,
	/**
	 * A traceroute reply.
	 *
	 * @see https://docs.scion.org/en/latest/protocols/scmp.html#traceroute-reply
	 */
	SCION_SCMP_TYPE_TRACEROUTE_REPLY = 131
};

/**
 * Gets the type of a SCMP message.
 * @param[in] buf The serialized SCMP message.
 * @param[in] buf_len The length of the SCMP message.
 * @return The type of the SCMP message. A type that is not defined by the SCMP specification is returned as it is,
 * and 0 if the buffer is too short.
 *
 * @see https://docs.scion.org/en/latest/protocols/scmp.html#types
 */
enum scion_scmp_type scion_scmp_get_type(const uint8_t *buf, uint16_t buf_len);

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
 * Gets a human-readable name for a SCMP message type.
 * @param[in] type The SCMP message type.
 * @return The name of the type, or "unknown" if the type is not defined by the SCMP specification.
 */
const char *scion_scmp_type_str(enum scion_scmp_type type);

/**
 * Gets a human-readable description of a SCMP message code.
 * @param[in] type The SCMP message type.
 * @param[in] code The SCMP message code.
 * @return The description of the code, "none" for code 0 of a type without codes, or "unknown" if the code is not
 * defined by the SCMP specification for the type.
 */
const char *scion_scmp_code_str(enum scion_scmp_type type, uint8_t code);

/**
 * The codes of a destination unreachable message.
 *
 * @see https://docs.scion.org/en/latest/protocols/scmp.html#destination-unreachable
 */
enum scion_scmp_code_destination_unreachable {
	SCION_SCMP_CODE_DESTINATION_UNREACHABLE_NO_ROUTE = 0,
	SCION_SCMP_CODE_DESTINATION_UNREACHABLE_ADMINISTRATIVELY_DENIED = 1,
	SCION_SCMP_CODE_DESTINATION_UNREACHABLE_BEYOND_SCOPE = 2,
	SCION_SCMP_CODE_DESTINATION_UNREACHABLE_ADDRESS_UNREACHABLE = 3,
	SCION_SCMP_CODE_DESTINATION_UNREACHABLE_PORT_UNREACHABLE = 4,
	SCION_SCMP_CODE_DESTINATION_UNREACHABLE_SOURCE_ADDRESS_FAILED_POLICY = 5,
	SCION_SCMP_CODE_DESTINATION_UNREACHABLE_REJECT_ROUTE = 6
};

/**
 * The codes of a parameter problem message.
 *
 * @see https://docs.scion.org/en/latest/protocols/scmp.html#parameter-problem
 */
enum scion_scmp_code_parameter_problem {
	SCION_SCMP_CODE_PARAMETER_PROBLEM_ERRONEOUS_HEADER_FIELD = 0,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_NEXT_HEADER = 1,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_COMMON_HEADER = 16,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_VERSION = 17,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_FLOW_ID_REQUIRED = 18,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_PACKET_SIZE = 19,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_PATH_TYPE = 20,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_ADDRESS_FORMAT = 21,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_ADDRESS_HEADER = 32,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_SOURCE_ADDRESS = 33,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_DESTINATION_ADDRESS = 34,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_NON_LOCAL_DELIVERY = 35,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_PATH = 48,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_HOP_FIELD_INGRESS = 49,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_HOP_FIELD_EGRESS = 50,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_HOP_FIELD_MAC = 51,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_PATH_EXPIRED = 52,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_SEGMENT_CHANGE = 53,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_INVALID_EXTENSION_HEADER = 64,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_HOP_BY_HOP_OPTION = 65,
	SCION_SCMP_CODE_PARAMETER_PROBLEM_UNKNOWN_END_TO_END_OPTION = 66
};

/**
 * An SCMP error message.
 *
 * Which member of @c info is used depends on @c type. A destination unreachable message has no further information.
 */
struct scion_scmp_error {
	/** the type, one of the error types */
	enum scion_scmp_type type;
	/** the code, see the enums above for the codes the specification defines */
	uint8_t code;
	/** the type specific information */
	union {
		/** for SCION_SCMP_TYPE_PACKET_TOO_BIG */
		struct {
			/** the maximum size of a SCION packet that fits the next-hop link */
			uint16_t mtu;
		} packet_too_big;
		/** for SCION_SCMP_TYPE_PARAMETER_PROBLEM */
		struct {
			/** the byte offset in the offending packet where the error was detected */
			uint16_t pointer;
		} parameter_problem;
		/** for SCION_SCMP_TYPE_EXTERNAL_INTERFACE_DOWN */
		struct {
			/** the ISD-AS of the router that originated the message */
			scion_ia ia;
			/** the interface of the external link that is down */
			scion_ifid interface;
		} external_interface_down;
		/** for SCION_SCMP_TYPE_INTERNAL_CONNECTIVITY_DOWN */
		struct {
			/** the ISD-AS of the router that originated the message */
			scion_ia ia;
			/** the interface on which the packet entered the AS */
			scion_ifid ingress_interface;
			/** the interface on which the packet was supposed to leave the AS */
			scion_ifid egress_interface;
		} internal_connectivity_down;
	} info;
	/** as much of the offending packet as fit into the message, or NULL */
	uint8_t *packet;
	/** the length of the offending packet in bytes */
	uint16_t packet_length;
};

/**
 * Determines how large the serialized SCMP error message will be.
 * @param[in] scmp_error The SCMP error message.
 * @return the size of the serialized SCMP error message in bytes, or 0 if the type is not a known SCMP error type.
 */
size_t scion_scmp_error_len(const struct scion_scmp_error *scmp_error);

/**
 * Serializes an SCMP error message.
 * @param[in] scmp_error The SCMP error message to serialize.
 * @param[out] buf The serialized SCMP error message.
 * @param[in] buf_len The length of the buffer.
 * @return 0 on success, a negative error code on failure.
 *
 * @note Use @link scion_scmp_error_len @endlink to determine how large the buffer needs to be.
 * @note The checksum is not set.
 */
int scion_scmp_error_serialize(const struct scion_scmp_error *scmp_error, uint8_t *buf, size_t buf_len);

/**
 * Deserializes an SCMP error message, for example inside an SCMP error callback.
 * @param[in] buf The serialized SCMP error message.
 * @param[in] buf_len The length of the serialized SCMP error message.
 * @param[out] scmp_error The SCMP error message.
 * @return 0 on success, SCION_ERR_PACKET_FIELD_INVALID if the type is not a known SCMP error type, another negative
 * error code on failure.
 *
 * @note The code and the checksum are not validated.
 * @note Free the members of the SCMP error message with @link scion_scmp_error_free_members @endlink.
 *
 * @see scion_setsockerrcb
 */
int scion_scmp_error_deserialize(const uint8_t *buf, size_t buf_len, struct scion_scmp_error *scmp_error);

/**
 * Frees the internal members of an SCMP error message.
 * @param[in] scmp_error The SCMP error message.
 */
void scion_scmp_error_free_members(struct scion_scmp_error *scmp_error);

/** The size of a buffer that is large enough for the string of any SCMP error message. */
#define SCION_SCMP_ERROR_STRLEN 128

/**
 * Gets the string representation of an SCMP error message, for example
 * "SCMP error: destination unreachable (port unreachable)".
 * @param[in] scmp_error The SCMP error message.
 * @param[out] buf The buffer in which the string is stored.
 * @param[in] buf_len The length of the buffer.
 * @return 0 on success, SCION_ERR_BUF_TOO_SMALL if the string does not fit in the buffer.
 *
 * @see The macro SCION_SCMP_ERROR_STRLEN can be used to allocate a buffer of appropriate size.
 */
int scion_scmp_error_str(const struct scion_scmp_error *scmp_error, char *buf, size_t buf_len);

/**
 * Prints an SCMP error message to stdout, for example "SCMP error: destination unreachable (port unreachable)".
 * @param[in] scmp_error The SCMP error message.
 */
void scion_scmp_error_print(const struct scion_scmp_error *scmp_error);

/**
 * An SCMP echo message.
 */
struct scion_scmp_echo {
	/** the type */
	enum scion_scmp_type type;
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

/** The size of a serialized SCMP traceroute message in bytes. */
#define SCION_SCMP_TRACEROUTE_LEN 24

/**
 * An SCMP traceroute message.
 */
struct scion_scmp_traceroute {
	/** the type */
	enum scion_scmp_type type;
	/** the identifier */
	uint16_t id;
	/** the sequence number */
	uint16_t seqno;
	/** the ISD-AS of the router that answered, 0 in a request */
	scion_ia ia;
	/** the interface of the router that answered, 0 in a request */
	scion_ifid interface;
};

/**
 * Serializes an SCMP traceroute message.
 * @param[in] scmp_traceroute The SCMP traceroute message to serialize.
 * @param[out] buf The serialized SCMP traceroute message.
 * @param[in] buf_len The length of the buffer.
 * @return 0 on success, a negative error code on failure.
 *
 * @note The buffer must be at least @ref SCION_SCMP_TRACEROUTE_LEN bytes long.
 */
int scion_scmp_traceroute_serialize(const struct scion_scmp_traceroute *scmp_traceroute, uint8_t *buf, size_t buf_len);

/**
 * Deserializes an SCMP traceroute message.
 * @param[in] buf The serialized SCMP traceroute message.
 * @param[in] buf_len The length of the serialized message.
 * @param[out] scmp_traceroute The SCMP traceroute message.
 * @return 0 on success, a negative error code on failure.
 */
int scion_scmp_traceroute_deserialize(
	const uint8_t *buf, size_t buf_len, struct scion_scmp_traceroute *scmp_traceroute);

/**
 * A callback for SCMP error handling.
 * @param scmp_error The SCMP error message that was received.
 * @param ctx The context that was provided when setting up the callback.
 *
 * @note The SCMP error message is freed after the callback returns. A callback that needs the quoted packet later has
 * to copy it.
 * @note A message that cannot be parsed, for example because of an unknown type, does not reach the callback.
 *
 * @see @link scion_setsockerrcb @endlink
 */
typedef void scion_socket_scmp_error_cb(const struct scion_scmp_error *scmp_error, void *ctx);

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
