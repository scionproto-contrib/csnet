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

#pragma once

#include <scion/scion_quic.h>

// Connects to the server (REMOTE_AS, REMOTE_HOST, REMOTE_PORT), sends MESSAGE, finishes the stream and prints the
// answer. The ALPN is set from ALPN, the rest of config (CA, server name, local address, debug) is used as given.
// Returns 0 if the server answered.
int simple_quic_client(const char *topology_path, const struct scion_quic_config *config);
