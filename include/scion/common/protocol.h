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

#include <arpa/inet.h>

/**
 * The address families that SCION supports.
 */
enum scion_addr_family { SCION_AF_IPV4 = AF_INET, SCION_AF_IPV6 = AF_INET6 };

/**
 * The protocols that SCION supports.
 */
enum scion_proto { SCION_PROTO_UDP = 17, SCION_PROTO_SCMP = 202 };
