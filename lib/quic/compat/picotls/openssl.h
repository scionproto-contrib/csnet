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

// ngtcp2's picotls crypto backend (crypto/picotls/picotls.c) is written for the OpenSSL binding of picotls. This
// header takes the place of <picotls/openssl.h> when that file is compiled and maps it to the mbedTLS binding, so the
// backend works without OpenSSL. Only for crypto/picotls/picotls.c, which uses exactly these symbols.

#pragma once

#include <picotls/mbedtls.h>

#define ptls_openssl_aes128gcm ptls_mbedtls_aes128gcm
#define ptls_openssl_aes256gcm ptls_mbedtls_aes256gcm
#define ptls_openssl_chacha20poly1305 ptls_mbedtls_chacha20poly1305
#define ptls_openssl_aes128ctr ptls_mbedtls_aes128ctr
#define ptls_openssl_aes256ctr ptls_mbedtls_aes256ctr
#define ptls_openssl_chacha20 ptls_mbedtls_chacha20
#define ptls_openssl_sha256 ptls_mbedtls_sha256
#define ptls_openssl_random_bytes ptls_mbedtls_random_bytes
#define PTLS_OPENSSL_HAVE_CHACHA20_POLY1305 1
