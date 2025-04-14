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

/**
 * @file error.h
 *
 * The errors of CSNET.
 */

#pragma once

#define SCION_GENERIC_ERR -1
#define SCION_MALLOC_FAIL -3
#define SCION_NO_PATHS -4
#define SCION_INVALID_NEXT_HOP -5
#define SCION_BUFFER_SIZE_ERR -6
#define SCION_NOT_ENOUGH_DATA -7
#define SCION_INVALID_FIELD -8
#define SCION_UNKNOWN_ADDR_TYPE -9
#define SCION_INVALID_SOCKET_FD -10
#define SCION_MAX_HDR_LEN_EXCEEDED -11
#define SCION_UNALIGNED_HDR -12
#define SCION_LEN_MISMATCH -13
#define SCION_GRPC_ERR -14
#define SCION_FILE_NOT_FOUND -15
#define SCION_JSON_LOAD_ERR -16
#define SCION_CORRUPT_TOPOLOGY -17
#define SCION_UNKNOWN_BR_IFID -18
#define SCION_SOCKET_ERR -19
#define SCION_IP_VERSION_MISMATCH -20
#define SCION_UNKNOWN_PROTO -21
#define SCION_NOT_CONNECTED -22
#define SCION_INVALID_META_HDR -23
#define SCION_DST_MISMATCH -24
#define SCION_INVALID_ISD_AS_STR -25
#define SCION_LOCAL_ISD_AS_MISMATCH -26
#define SCION_UNDEFINED_ADDR -27
#define SCION_INVALID_PATH_TYPE -28
#define SCION_WOULD_BLOCK -29
#define SCION_BIND_ERR -30
#define SCION_INVALID_ADDR -31
#define SCION_ALREADY_BOUND -32
#define SCION_FLAG_NOT_IMPLEMENTED -33
#define SCION_FLAG_NOT_SUPPORTED -34
#define SCION_SEND_ERR -35
#define SCION_RECV_ERR -36
#define SCION_ADDR_IN_USE -37
#define SCION_ADDR_NOT_AVAILABLE -38
#define SCION_NO_MEM -39
#define SCION_OUTPUT_QUEUE_FULL -40
#define SCION_INVALID_BUFFER -41
#define SCION_SOCK_OPT_ERR -42
#define SCION_INVALID_SOCK_OPT -43
#define SCION_INVALID_SCMP_TYPE -44
#define SCION_INVALID_SCMP_CODE -45
#define SCION_ADDR_BUF_ERR -46
#define SCION_PATH_EXPIRED -47
#define SCION_NETWORK_SOURCE_ADDR_ERR -48
#define SCION_NOT_BOUND -49
#define SCION_NETWORK_UNKNOWN -50
#define SCION_MSG_TOO_LARGE -51

char *scion_strerror(int err);
