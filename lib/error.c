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

#include "scion/scion.h"

char *scion_strerror(int err)
{
	switch (err) {
	case SCION_GENERIC_ERR:
		return "generic error";
	case SCION_MALLOC_FAIL:
		return "malloc failure";
	case SCION_NO_PATHS:
		return "no paths";
	case SCION_INVALID_NEXT_HOP:
		return "invalid next hop";
	case SCION_BUFFER_SIZE_ERR:
		return "buffer size error";
	case SCION_NOT_ENOUGH_DATA:
		return "not enough data";
	case SCION_INVALID_FIELD:
		return "invalid field";
	case SCION_UNKNOWN_ADDR_TYPE:
		return "unknown address type";
	case SCION_INVALID_SOCKET_FD:
		return "invalid socket fd";
	case SCION_MAX_HDR_LEN_EXCEEDED:
		return "max header length exceeded";
	case SCION_UNALIGNED_HDR:
		return "unaligned header";
	case SCION_LEN_MISMATCH:
		return "length mismatch";
	case SCION_GRPC_ERR:
		return "grpc error";
	case SCION_FILE_NOT_FOUND:
		return "file not found";
	case SCION_JSON_LOAD_ERR:
		return "json load error";
	case SCION_CORRUPT_TOPOLOGY:
		return "corrupt topology";
	case SCION_UNKNOWN_BR_IFID:
		return "unknown border router IFID";
	case SCION_SOCKET_ERR:
		return "socket error";
	case SCION_IP_VERSION_MISMATCH:
		return "IP version mismatch";
	case SCION_UNKNOWN_PROTO:
		return "unknown protocol";
	case SCION_NOT_CONNECTED:
		return "not connected";
	case SCION_INVALID_META_HDR:
		return "invalid meta header";
	case SCION_DST_MISMATCH:
		return "destination mismatch";
	case SCION_INVALID_ISD_AS_STR:
		return "invalid ISD AS string";
	case SCION_LOCAL_ISD_AS_MISMATCH:
		return "local ISD AS mismatch";
	case SCION_UNDEFINED_ADDR:
		return "undefined address";
	case SCION_INVALID_PATH_TYPE:
		return "invalid path type";
	case SCION_WOULD_BLOCK:
		return "would block";
	case SCION_BIND_ERR:
		return "bind error";
	case SCION_INVALID_ADDR:
		return "invalid address";
	case SCION_ALREADY_BOUND:
		return "socket already bound";
	case SCION_FLAG_NOT_IMPLEMENTED:
		return "flag not implemented";
	case SCION_FLAG_NOT_SUPPORTED:
		return "flag not supported";
	case SCION_SEND_ERR:
		return "send error";
	case SCION_RECV_ERR:
		return "receive error";
	case SCION_ADDR_IN_USE:
		return "address is already in use";
	case SCION_ADDR_NOT_AVAILABLE:
		return "a nonexistent interface was requested or the address is not local";
	case SCION_NO_MEM:
		return "not enough memory";
	case SCION_OUTPUT_QUEUE_FULL:
		return "output queue is full";
	case SCION_INVALID_BUFFER:
		return "invalid buffer provided";
	case SCION_SOCK_OPT_ERR:
		return "socket operation error";
	case SCION_INVALID_SOCK_OPT:
		return "invalid socket option";
	case SCION_INVALID_SCMP_TYPE:
		return "invalid SCMP type";
	case SCION_INVALID_SCMP_CODE:
		return "invalid SCMP code";
	case SCION_ADDR_BUF_ERR:
		return "address buffer error";
	case SCION_PATH_EXPIRED:
		return "path expired";
	case SCION_NETWORK_SOURCE_ADDR_ERR:
		return "could not determine network source address";
	case SCION_NOT_BOUND:
		return "socket is not bound";
	case SCION_NETWORK_UNKNOWN:
		return "nework unknown";
	case SCION_MSG_TOO_LARGE:
		return "message too large";
	default:
		return "unknown error";
	}
}
