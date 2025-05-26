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

int scion_test_serialize_udp(void);
int scion_test_serialize_meta_hdr(void);
int scion_test_serialize_info_field(void);
int scion_test_serialize_hop_field(void);
int scion_test_serialize_path(void);
int scion_test_serialize_scion_packet(void);
int scion_test_serialize_scmp_echo(void);
