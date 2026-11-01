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

// mbedTLS 4 (TF-PSA-Crypto) moved the raw ChaCha20 API, which picotls uses for QUIC header protection, to a private
// header. Only with mbedTLS >= 4; the build also defines MBEDTLS_DECLARE_PRIVATE_IDENTIFIERS for that file, as
// <psa/crypto.h> may include the private header before this one.

#pragma once

#include <mbedtls/private/chacha20.h>
