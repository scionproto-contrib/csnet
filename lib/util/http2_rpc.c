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

#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <netdb.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <sys/socket.h>
#include <unistd.h>

#include <nghttp2/nghttp2.h>
#include <zlib.h>

#include "util/http2_rpc.h"

// MAKE_NV based on nghttp2 - HTTP/2 client tutorial, by Tatsuhiro Tsujikawa
// https://nghttp2.org/documentation/tutorial-client.html
// clang-format off
#define MAKE_NV(NAME, VALUE)                                                                 \
	{                                                                                        \
		(uint8_t *)NAME, (uint8_t *)VALUE, strlen(NAME), strlen(VALUE), NGHTTP2_NV_FLAG_NONE \
	}
// clang-format on

typedef struct http2_rpc_data {
	const uint8_t *data;
	size_t data_length;
} http2_rpc_data;

static int decompress_grpc_response(http2_rpc_handle *hd)
{
	if (hd->bytes_written < 7) {
		return 1;
	}

	// Check if gRPC response starts with compression flag and has gzip magic bytes
	if ((unsigned char)hd->output_buffer[0] != 0x01) {
		// No compression flag found, data appears uncompressed
		return 1;
	}

	// Check for gzip magic bytes
	if ((unsigned char)hd->output_buffer[5] != 0x1f || (unsigned char)hd->output_buffer[6] != 0x8b) {
		// No gzip magic bytes found at offset
		return -1;
	}

	z_stream stream;
	(void)memset(&stream, 0, sizeof stream);

	int ret = inflateInit2(&stream, 15 + 32); // Auto-detect gzip/deflate
	if (ret != Z_OK) {
		return -1;
	}

	stream.avail_in = (uInt)(hd->bytes_written - 5);
	stream.next_in = (Bytef *)(hd->output_buffer + 5);

	size_t decompressed_len = 0;
	size_t decompressed_cap = 4096;
	char *decompressed_data = malloc(decompressed_cap);
	if (!decompressed_data) {
		inflateEnd(&stream);
		return -1;
	}

	do {
		const size_t min_avail_out = 1024;
		if (decompressed_cap - decompressed_len < min_avail_out) {
			decompressed_cap += min_avail_out;
			void *new_buffer = realloc(decompressed_data, decompressed_cap);
			if (!new_buffer) {
				free(decompressed_data);
				inflateEnd(&stream);
				return -1;
			}
			decompressed_data = new_buffer;
		}

		size_t avail_out = decompressed_cap - decompressed_len;
		stream.avail_out = (uInt)avail_out;
		stream.next_out = (Bytef *)(decompressed_data + decompressed_len);

		ret = inflate(&stream, Z_NO_FLUSH);
		if (ret == Z_NEED_DICT) {
			ret = Z_DATA_ERROR;
		}
		if (ret == Z_STREAM_ERROR || ret == Z_DATA_ERROR || ret == Z_MEM_ERROR) {
			free(decompressed_data);
			(void)inflateEnd(&stream);
			return -1;
		}

		decompressed_len += avail_out - stream.avail_out;
	} while (stream.avail_out == 0);

	if (ret != Z_STREAM_END) {
		free(decompressed_data);
		(void)inflateEnd(&stream);
		return -1;
	}
	
	(void)inflateEnd(&stream);

	free(hd->output_buffer);
	hd->output_buffer = decompressed_data;
	hd->output_buffer_size = decompressed_cap;
	hd->bytes_written = decompressed_len;

	return 0;
}

/*
 * ###################### Send HTTP/2 Ping function ######################
 */

int http2_rpc_send_ping(http2_rpc_handle *hd)
{
	int ret;
	uint8_t ping_data[8];
#if defined(__APPLE__)
	arc4random_buf(ping_data, sizeof ping_data);
#else
	ssize_t generated_bytes = getrandom(ping_data, sizeof ping_data, 0x0001 /* GRND_NONBLOCK */);
	if (generated_bytes < 0 || (size_t)generated_bytes < sizeof ping_data) {
		return -1;
	}
#endif

	ret = nghttp2_submit_ping(hd->nghttp2_session, NGHTTP2_FLAG_NONE, (const uint8_t *)ping_data);
	if (ret != 0) {
		return -1;
	}
	return 0;
}

static int grow_output_buffer(http2_rpc_handle *hd, size_t min)
{
	size_t new_size = hd->output_buffer_size;

	while (new_size < min) {
		new_size *= 2;
	}

	void *new_buffer = realloc(hd->output_buffer, new_size);

	if (new_buffer == NULL) {
		return -1;
	}

	hd->output_buffer = new_buffer;
	hd->output_buffer_size = new_size;

	return 0;
}

/*
 * ##################################################################
 * ####################### CALLBACK FUNCTIONS #######################
 * ##################################################################
 */

/*
 * ###################### Data provider function ######################
 */

/*
 * protobuf messages are prefixed by 5 bytes:
 * |-- (1 Byte) Compression --|-- (4 Bytes) length of protobuf message in big endian --|
 * Compression is always 0x00.
 */

ssize_t data_provider_cb(nghttp2_session *session, int32_t stream_id, uint8_t *buf, size_t length, uint32_t *data_flags,
	nghttp2_data_source *source, void *user_data)
{
	(void)session;
	(void)stream_id;
	(void)user_data;

	http2_rpc_data rpc_data = *((http2_rpc_data *)source->ptr);

	size_t copied_length = rpc_data.data_length + 5;

	if (length < copied_length) {
		copied_length = 0;
	} else {
		// Add compression and length
		buf[0] = 0x00;
		buf[1] = (uint8_t)((rpc_data.data_length >> 24) & 0xff);
		buf[2] = (uint8_t)((rpc_data.data_length >> 16) & 0xff);
		buf[3] = (uint8_t)((rpc_data.data_length >> 8) & 0xff);
		buf[4] = (uint8_t)(rpc_data.data_length & 0xff);
		(void)memcpy(buf + 5, rpc_data.data, rpc_data.data_length);
	}

	(*data_flags) |= NGHTTP2_DATA_FLAG_EOF;

	assert(copied_length < SSIZE_MAX);
	return (ssize_t)copied_length;
}

/*
 * ###################### nghttp2_send_callback ######################
 */

/*
 * Implementation of nghttp2_send_callback. From nghttp2 API reference:
 *
 * Callback function invoked when session wants to send data to the remote peer. The implementation
 * of this function must send at most length bytes of data stored in data. The flags is currently
 * not used and always 0. It must return the number of bytes sent if it succeeds. If it cannot send
 * any single byte without blocking, it must return nghttp2_error.NGHTTP2_ERR_WOULDBLOCK. For other
 * errors, it must return nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE.
 */

// Based on idf-extra-components/sh2lib/sh2lib.c by Espressif Systems (Shanghai) CO LTD
// https://github.com/espressif/idf-extra-components/blob/master/sh2lib/sh2lib.c

static ssize_t callback_send_inner(http2_rpc_handle *hd, const uint8_t *data, size_t length)
{
	ssize_t ret = send(hd->socket_fd, data, length, 0);
	if (ret <= 0) {
		// TODO change to correct error messages using errno.
		if (errno == EWOULDBLOCK) {
			ret = NGHTTP2_ERR_WOULDBLOCK;
		} else {
			ret = NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	}
	return ret;
}

static ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data)
{
	(void)session;
	(void)flags;

	ssize_t ret = 0;
	http2_rpc_handle *hd = (http2_rpc_handle *)user_data;

	size_t copy_offset = 0;
	size_t pending_data = length;

	/* Send data in 1000 byte chunks */
	while (copy_offset != length) {
		size_t chunk_len = pending_data > 1000 ? 1000 : pending_data;
		ssize_t subret = callback_send_inner(hd, data + copy_offset, chunk_len);
		if (subret <= 0) {
			if (copy_offset == 0) {
				/* If no data is transferred, send the error code */
				ret = subret;
			}
			break;
		}
		copy_offset += (size_t)subret;
		pending_data -= (size_t)subret;
		ret += subret;
	}
	return ret;
}

/*
 * ###################### nghttp2_recv_callback ######################
 */

/*
 * Implementation of nghttp2_recv_callback. From nghttp2 API reference:
 *
 * Callback function invoked when session wants to receive data from the remote peer. The implementation
 * of this function must read at most length bytes of data and store it in buf. The flags is currently
 * not used and always 0. It must return the number of bytes written in buf if it succeeds. If it cannot
 * read any single byte without blocking, it must return nghttp2_error.NGHTTP2_ERR_WOULDBLOCK. If it
 * gets EOF before it reads any single byte, it must return nghttp2_error.NGHTTP2_ERR_EOF. For other
 * errors, it must return nghttp2_error.NGHTTP2_ERR_CALLBACK_FAILURE. Returning 0 is treated as
 * nghttp2_error.NGHTTP2_ERR_WOULDBLOCK.
 */

// Based on idf-extra-components/sh2lib/sh2lib.c by Espressif Systems (Shanghai) CO LTD
// https://github.com/espressif/idf-extra-components/blob/master/sh2lib/sh2lib.c

static ssize_t recv_callback(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data)
{
	(void)session;
	(void)flags;

	http2_rpc_handle *hd = (http2_rpc_handle *)user_data;
	ssize_t ret = recv(hd->socket_fd, buf, length, 0);
	if (ret < 0) {
		if (errno == EWOULDBLOCK) {
			ret = NGHTTP2_ERR_WOULDBLOCK;
		} else {
			ret = NGHTTP2_ERR_CALLBACK_FAILURE;
		}
	} else if (ret == 0) {
		ret = NGHTTP2_ERR_EOF;
	}
	return ret;
}

/*
 * ###################### nghttp2_on_stream_close_callback ######################
 */

/*
 * Implementation of nghttp2_on_stream_close_callback. From nghttp2 API reference:
 *
 * Callback function invoked when the stream stream_id is closed. The reason of closure is indicated
 * by the error_code. The error_code is usually one of nghttp2_error_code, but that is not guaranteed.
 */

static int on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data)
{
	(void)stream_id;
	(void)error_code;
	(void)user_data;

	// ESP_LOGI(TAG, "[stream-close][sid %" PRIi32 "]", stream_id);
	int ret;
	ret = nghttp2_session_terminate_session(session, NGHTTP2_NO_ERROR);
	if (ret != 0) {
		return NGHTTP2_ERR_CALLBACK_FAILURE;
	}
	return 0;
}

/*
 * ###################### nghttp2_on_data_chunk_recv_callback ######################
 */

/*
 * Implementation of nghttp2_on_data_chunk_recv_callback. From nghttp2 API reference:
 *
 * Callback function invoked when a chunk of data in DATA frame is received. The stream_id is the stream ID
 * this DATA frame belongs to. The flags is the flags of DATA frame which this data chunk is contained.
 * (flags & NGHTTP2_FLAG_END_STREAM) != 0 does not necessarily mean this chunk of data is the last one in the
 * stream. You should use nghttp2_on_frame_recv_callback to know all data frames are received.
 */

static int on_data_chunk_recv_callback(
	nghttp2_session *session, uint8_t flags, int32_t stream_id, const uint8_t *data, size_t len, void *user_data)
{
	(void)session;
	(void)flags;
	(void)stream_id;

	if (len > 0) {
		http2_rpc_handle *hd = (http2_rpc_handle *)user_data;
		size_t offset = hd->bytes_written;
		size_t maxlen = hd->output_buffer_size;

		if (offset + len > maxlen) {
			int ret = grow_output_buffer(hd, offset + len);

			if (ret != 0) {
				return -1;
			}
		}
		(void)memcpy((hd->output_buffer) + offset, data, len);
		hd->bytes_written = offset + len;
	}
	return 0;
}

/*
 * ###################### nghttp2_on_header_callback ######################
 */

static int on_header_callback(nghttp2_session *session, const nghttp2_frame *frame, const uint8_t *name, size_t namelen,
	const uint8_t *value, size_t valuelen, uint8_t flags, void *user_data)
{
	(void)session;
	(void)frame;
	(void)valuelen;
	(void)flags;

	http2_rpc_handle *hd = (http2_rpc_handle *)user_data;
	if (strncmp("grpc-status", (const char *)name, namelen) == 0) {
		hd->grpc_status_code = atoi((const char *)value);
	}
	return 0;
}

/*
 * ##################################################################
 * ##################  http2_rpc_handle functions ###################
 * ##################################################################
 */

/*
 * ###################### initialize handle function ######################
 */

int http2_rpc_handle_init(http2_rpc_handle *hd, const char *dst_hostname, struct sockaddr *dst_addr,
	socklen_t dst_addr_len, size_t initial_output_buffer_size)
{
	(void)memset(hd, 0, sizeof(*hd));

	hd->socket_fd = -1;

	size_t hostname_len = strlen(dst_hostname) + 1;
	hd->dst_hostname = malloc(hostname_len);
	(void)strncpy(hd->dst_hostname, dst_hostname, hostname_len);
	hd->dst_addr = dst_addr;
	hd->dst_addr_len = dst_addr_len;

	hd->output_buffer_size = initial_output_buffer_size;
	hd->output_buffer = malloc(initial_output_buffer_size);
	hd->bytes_written = 0;

	hd->grpc_status_code = -1;

	return 0;
}

/*
 * ###################### free handle function ######################
 */

void http2_rpc_handle_free(http2_rpc_handle *hd)
{
	if (hd->nghttp2_session) {
		nghttp2_session_del(hd->nghttp2_session);
		hd->nghttp2_session = NULL;
	}
	if (hd->socket_fd != -1) {
		(void)shutdown(hd->socket_fd, 0);
		(void)close(hd->socket_fd);
		hd->socket_fd = -1;
	}
	if (hd->dst_hostname) {
		free(hd->dst_hostname);
		hd->dst_hostname = NULL;
	}
	if (hd->output_buffer) {
		free(hd->output_buffer);
		hd->output_buffer = NULL;
	}
}

/*
 * ##################################################################
 * ######################## Setup functions #########################
 * ##################################################################
 */

static int nghttp2_init(http2_rpc_handle *hd)
{
	int ret;

	nghttp2_session_callbacks *callbacks;
	ret = nghttp2_session_callbacks_new(&callbacks);
	if (ret != 0) {
		return -1;
	}
	nghttp2_session_callbacks_set_send_callback(callbacks, send_callback);
	nghttp2_session_callbacks_set_recv_callback(callbacks, recv_callback);
	nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, on_stream_close_callback);
	nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, on_data_chunk_recv_callback);
	nghttp2_session_callbacks_set_on_header_callback(callbacks, on_header_callback);

	ret = nghttp2_session_client_new(&hd->nghttp2_session, callbacks, hd);
	nghttp2_session_callbacks_del(callbacks);
	if (ret != 0) {
		return -1;
	}

	ret = nghttp2_submit_settings(hd->nghttp2_session, NGHTTP2_FLAG_NONE, NULL, 0);
	if (ret != 0) {
		return -1;
	}

	return 0;
}

int http2_rpc_connect(http2_rpc_handle *hd)
{
	int ret;

	hd->socket_fd = socket(hd->dst_addr->sa_family, SOCK_STREAM, 0);
	if (hd->socket_fd == -1) {
		http2_rpc_handle_free(hd);
		return -1;
	}

	ret = connect(hd->socket_fd, hd->dst_addr, hd->dst_addr_len);
	if (ret != 0) {
		http2_rpc_handle_free(hd);
		return ret;
	}

	struct timeval receiving_timeout;
	receiving_timeout.tv_sec = 1;
	receiving_timeout.tv_usec = 0;
	if (setsockopt(hd->socket_fd, SOL_SOCKET, SO_RCVTIMEO, &receiving_timeout, sizeof(receiving_timeout)) < 0) {
		return -1;
	}

	struct linger linger;
	linger.l_onoff = 1;
	linger.l_linger = 0;
	(void)setsockopt(hd->socket_fd, SOL_SOCKET, SO_LINGER, &linger, sizeof(linger));

	// Set socket to non-blocking
	int flags = fcntl(hd->socket_fd, F_GETFL, 0);
	if (fcntl(hd->socket_fd, F_SETFL, O_NONBLOCK | flags) < 0) {
		return -1;
	}

	ret = nghttp2_init(hd);
	if (ret != 0) {
		http2_rpc_handle_free(hd);
		return ret;
	}
	return 0;
}

/*
 * ##################################################################
 * ####################### General functions ########################
 * ##################################################################
 */

/*
 * ###################### perform read write function ######################
 */

int http2_rpc_perform_read_write(http2_rpc_handle *hd)
{
	int ret;
	int want_write = nghttp2_session_want_write(hd->nghttp2_session);
	int want_read = nghttp2_session_want_read(hd->nghttp2_session);

	while (want_write || want_read) {
		if (want_write) {
			ret = nghttp2_session_send(hd->nghttp2_session);
			if (ret != 0) {
				return ret;
			}
		}

		if (want_read) {
			ret = nghttp2_session_recv(hd->nghttp2_session);
			if (ret != 0 && ret != NGHTTP2_ERR_EOF) {
				return ret;
			}
		}

		want_write = nghttp2_session_want_write(hd->nghttp2_session);
		want_read = nghttp2_session_want_read(hd->nghttp2_session);
	}
	return 0;
}

/*
 * ###################### Request function ######################
 */

int http2_rpc_request(http2_rpc_handle *hd, const char *path, const u_int8_t *data, size_t data_length)
{
	int ret;

	ret = http2_rpc_connect(hd);
	if (ret != 0) {
		http2_rpc_handle_free(hd);
		return -1;
	}

	(void)http2_rpc_send_ping(hd);

	http2_rpc_data rpc_data = { .data = data, .data_length = data_length };

	const nghttp2_nv headers[] = { MAKE_NV(":method", "POST"), MAKE_NV(":scheme", "http"),
		MAKE_NV(":authority", hd->dst_hostname), MAKE_NV(":path", path), MAKE_NV("te", "trailers"),
		MAKE_NV("content-type", "application/grpc+proto"), MAKE_NV("grpc-accept-encoding", "identity, deflate, gzip"),
		MAKE_NV("user-agent", "grpc-csnet/custom") };

	nghttp2_data_provider data_provider;
	data_provider.read_callback = data_provider_cb;
	data_provider.source.ptr = &rpc_data;

	ret = nghttp2_submit_request(
		hd->nghttp2_session, NULL, headers, sizeof(headers) / sizeof(headers[0]), &data_provider, hd);
	if (ret < 0) {
		http2_rpc_handle_free(hd);
		return ret;
	}

	ret = http2_rpc_perform_read_write(hd);
	if (ret < 0) {
		http2_rpc_handle_free(hd);
		return ret;
	}

	// Attempt to decompress gRPC response if it's gzip compressed
	ret = decompress_grpc_response(hd);
	if (ret < 0) {
		http2_rpc_handle_free(hd);
		return -1;
	}
	if (ret > 0) {
		if (hd->bytes_written >= 5) {
			(void)memmove(hd->output_buffer, hd->output_buffer + 5, hd->bytes_written - 5);
			hd->bytes_written -= 5;
		}
	}
	return 0;
}
