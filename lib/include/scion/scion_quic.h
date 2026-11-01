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
 * @file scion_quic.h
 *
 * QUIC client connections over SCION (optional library `scion_quic`, built with `-DBUILD_QUIC=ON`).
 *
 * A connection carries one bidirectional stream, which is opened by the client once the handshake is done. This is
 * the mapping used by most "X over QUIC" protocols with a single conversation, e.g. MQTT over QUIC (ALPN "mqtt").
 * QUIC packets are limited to 1200 bytes, which fits the MTU of any SCION path.
 *
 * The API does not own an event loop. Either call scion_quic_wait() in a loop, or integrate the connection into an
 * existing loop: wait until the file descriptor of scion_quic_getfd() is readable or scion_quic_timeout() elapsed,
 * then call scion_quic_process().
 *
 * TLS 1.3 is provided by a backend chosen at build time (`-DSCION_QUIC_TLS=quictls|picotls`). picotls uses mbedTLS
 * for its cryptography and runs on the ESP32.
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "scion/scion.h"

struct scion_policy;

/**
 * @struct scion_quic_conn
 *
 * @brief A QUIC client connection over SCION with a single bidirectional stream.
 */
struct scion_quic_conn;

/**
 * @struct scion_quic_config
 *
 * @brief Configuration of a QUIC connection.
 */
struct scion_quic_config {
	/**
	 * The application protocol (ALPN), e.g. "mqtt". Required.
	 */
	const char *alpn;
	/**
	 * The server name sent in the TLS handshake (SNI). If ca_pem is set, the certificate of the server must be valid
	 * for this name. May be NULL.
	 */
	const char *server_name;
	/**
	 * The trusted CA certificates in PEM format. If NULL, the certificate of the server is NOT verified.
	 */
	const char *ca_pem;
	/**
	 * The length of ca_pem in bytes.
	 */
	size_t ca_pem_len;
	/**
	 * The local address to bind to, e.g. the address of the Wi-Fi interface of an ESP32. May be NULL.
	 */
	const struct sockaddr *local_addr;
	/**
	 * The length of local_addr.
	 */
	socklen_t local_addrlen;
	/**
	 * The path policy of the underlying SCION socket. May be NULL (default policy).
	 */
	const struct scion_policy *policy;
	/**
	 * Print a packet level log of the QUIC connection to stderr.
	 */
	bool debug;
};

/**
 * Starts a QUIC connection to a SCION address. The handshake continues while the connection is processed (see
 * scion_quic_wait() and scion_quic_process()); data written before it completes is queued.
 * @param[out] conn The new connection.
 * @param network The SCION network.
 * @param addr The IP address and port of the server.
 * @param addrlen The length of addr.
 * @param ia The ISD-AS of the server.
 * @param config The configuration.
 * @return 0 on success, a negative error code on failure.
 */
int scion_quic_connect(struct scion_quic_conn **conn, struct scion_network *network, const struct sockaddr *addr,
	socklen_t addrlen, scion_ia ia, const struct scion_quic_config *config);

/**
 * Returns the file descriptor of the underlying socket, to wait for incoming packets.
 * @param conn The connection.
 * @param[out] fd The file descriptor.
 * @return 0 on success, a negative error code on failure.
 */
int scion_quic_getfd(const struct scion_quic_conn *conn, int *fd);

/**
 * Returns the time in milliseconds until scion_quic_process() has to be called even if no packet arrived.
 * @param conn The connection.
 * @return The timeout in milliseconds (0 if now), or -1 if no timer is pending.
 */
int scion_quic_timeout(const struct scion_quic_conn *conn);

/**
 * Receives the pending packets, handles the timers and sends what is due (data, acknowledgements,
 * retransmissions). Does not block.
 * @param conn The connection.
 * @return 0 while the connection is alive, a negative error code once it is closed or failed.
 */
int scion_quic_process(struct scion_quic_conn *conn);

/**
 * Waits for packets or the next timer, at most timeout_ms, and processes the connection.
 * @param conn The connection.
 * @param timeout_ms The maximum time to wait in milliseconds, -1 for no limit.
 * @return 0 while the connection is alive, a negative error code once it is closed or failed.
 */
int scion_quic_wait(struct scion_quic_conn *conn, int timeout_ms);

/**
 * Returns whether the handshake completed and the stream is open.
 * @param conn The connection.
 * @return true if the connection is established.
 */
bool scion_quic_is_established(const struct scion_quic_conn *conn);

/**
 * Queues data on the stream and sends as much as flow control allows. The data is copied.
 * @param conn The connection.
 * @param buf The data.
 * @param len The length of the data.
 * @return The number of bytes queued (len), or a negative error code.
 */
ssize_t scion_quic_write(struct scion_quic_conn *conn, const void *buf, size_t len);

/**
 * Finishes the sending side of the stream (FIN) after the queued data.
 * @param conn The connection.
 * @return 0 on success, a negative error code on failure.
 */
int scion_quic_shutdown(struct scion_quic_conn *conn);

/**
 * Reads received stream data. Does not block.
 * @param conn The connection.
 * @param buf The buffer.
 * @param len The size of the buffer.
 * @return The number of bytes read, 0 if the server finished its side of the stream and all data was read,
 * SCION_ERR_WOULD_BLOCK if no data is available yet, or another negative error code if the connection failed.
 */
ssize_t scion_quic_read(struct scion_quic_conn *conn, void *buf, size_t len);

/**
 * Closes the connection (sends a CONNECTION_CLOSE) and frees it, including the underlying socket.
 * @param conn The connection. May be NULL.
 */
void scion_quic_close(struct scion_quic_conn *conn);

#ifdef __cplusplus
}
#endif
