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

// The TLS backend of the QUIC client: one implementation per TLS library (tls_quictls.c, tls_picotls.c), selected at
// build time. Everything else in quic.c is independent of the TLS library.

#pragma once

#include <stddef.h>
#include <stdint.h>

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>

#include "scion/scion_quic.h"

struct scion_quic_tls;

// Creates the TLS state of a client connection: ALPN, SNI and, if config->ca_pem is set, server verification.
// conn_ref is what the ngtcp2 crypto backend uses to find the ngtcp2_conn.
int scion_quic_tls_new(
	struct scion_quic_tls **tls, const struct scion_quic_config *config, ngtcp2_crypto_conn_ref *conn_ref);

// Binds the TLS state to the QUIC connection (ngtcp2_conn_set_tls_native_handle). Called once conn exists.
int scion_quic_tls_attach(struct scion_quic_tls *tls, ngtcp2_conn *conn);

void scion_quic_tls_free(struct scion_quic_tls *tls);

// Cryptographically secure random bytes (connection IDs, tokens).
int scion_quic_tls_random(uint8_t *buf, size_t len);
