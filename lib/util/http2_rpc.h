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

#include <nghttp2/nghttp2.h>

typedef struct http2_rpc_handle {
	nghttp2_session *nghttp2_session;
	int socket_fd;

	char *dst_hostname;
	struct sockaddr *dst_addr;
	socklen_t dst_addr_len;

	char *output_buffer;
	size_t output_buffer_size;
	size_t bytes_written;

	int grpc_status_code;
} http2_rpc_handle;

int http2_rpc_handle_init(http2_rpc_handle *hd, const char *dst_hostname, struct sockaddr *dst_addr,
	socklen_t dst_addr_len, size_t initial_output_buffer_size);

int http2_rpc_request(http2_rpc_handle *hd, const char *path, const uint8_t *data, size_t data_length);

void http2_rpc_handle_free(http2_rpc_handle *hd);
