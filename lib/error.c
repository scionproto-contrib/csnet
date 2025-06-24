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
	case SCION_ERR_GENERIC_ERR:
		return "generic error";
	case SCION_ERR_MEM_ALLOC_FAIL:
		return "memory allocation failed";
	case SCION_ERR_NO_PATHS:
		return "no paths";
	case SCION_ERR_BUFFER_SIZE_ERR:
		return "buffer size error";
	case SCION_ERR_NOT_ENOUGH_DATA:
		return "not enough data";
	case SCION_ERR_PACKET_FIELD_INVALID:
		return "invalid packet field";
	case SCION_ERR_ADDR_FAMILY_UNKNOWN:
		return "unknown address family";
	case SCION_ERR_MAX_HDR_LEN_EXCEEDED:
		return "max header length exceeded";
	case SCION_ERR_GRPC_ERR:
		return "grpc error";
	case SCION_ERR_FILE_NOT_FOUND:
		return "file not found";
	case SCION_ERR_TOPOLOGY_INVALID:
		return "invalid topology";
	case SCION_ERR_ADDR_FAMILY_MISMATCH:
		return "address family mismatch";
	case SCION_ERR_NETWORK_ADDR_FAMILY_MISMATCH:
		return "network address family mismatch";
	case SCION_ERR_PROTO_UNKNOWN:
		return "unknown protocol";
	case SCION_ERR_NOT_CONNECTED:
		return "not connected";
	case SCION_ERR_META_HDR_INVALID:
		return "invalid meta header";
	case SCION_ERR_DST_MISMATCH:
		return "destination IA mismatch";
	case SCION_ERR_INVALID_ISD_AS_STR:
		return "invalid ISD AS string";
	case SCION_ERR_PATH_TYPE_INVALID:
		return "invalid path type";
	case SCION_ERR_WOULD_BLOCK:
		return "would block";
	case SCION_ERR_ADDR_INVALID:
		return "invalid address";
	case SCION_ERR_ALREADY_BOUND:
		return "socket already bound";
	case SCION_ERR_FLAG_NOT_IMPLEMENTED:
		return "flag not implemented";
	case SCION_ERR_FLAG_NOT_SUPPORTED:
		return "flag not supported";
	case SCION_ERR_SEND_ERR:
		return "send error";
	case SCION_ERR_RECV_ERR:
		return "receive error";
	case SCION_ERR_ADDR_IN_USE:
		return "address is already in use";
	case SCION_ERR_ADDR_NOT_AVAILABLE:
		return "a nonexistent interface was requested or the address is not local";
	case SCION_ERR_OUTPUT_QUEUE_FULL:
		return "output queue is full";
	case SCION_ERR_SOCK_OPT_INVALID:
		return "invalid socket option";
	case SCION_ERR_SCMP_CODE_INVALID:
		return "invalid SCMP code";
	case SCION_ERR_ADDR_BUF_ERR:
		return "address buffer error";
	case SCION_ERR_PATH_EXPIRED:
		return "path expired";
	case SCION_ERR_NOT_BOUND:
		return "socket is not bound";
	case SCION_ERR_NETWORK_UNKNOWN:
		return "network unknown";
	case SCION_ERR_MSG_TOO_LARGE:
		return "message too large";
	case SCION_ERR_SRC_ADDR_UNKNOWN:
		return "source address unknown";
	default:
		return "unknown error";
	}
}
