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

// The control-plane PKI of SCION: TRCs, certificate chains and the signatures of the control plane.
// https://docs.scion.org/en/latest/cryptography/index.html

#pragma once

#include <mbedtls/x509_crt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/uio.h>
#include <time.h>

#include "common/isd_as.h"
#include "scion/scion.h"

/*
 * A TRC (trust root configuration) of an ISD. It holds the root certificates that the certificate chains of the ASes
 * of the ISD are verified against.
 */
struct scion_trc {
	scion_isd isd;
	uint64_t base;
	uint64_t serial;
	time_t not_before;
	time_t not_after;
	// The time in seconds after not_before during which the previous TRC is still valid, 0 for a base TRC
	uint32_t grace_period;
	bool no_trust_reset;
	uint8_t quorum;
	mbedtls_x509_crt roots;
	// The encoding of the TRC
	uint8_t *der;
	size_t der_len;
};

/*
 * Parses a TRC from its DER encoding, a CMS signed message. The signatures of the TRC are not verified, so the TRC must
 * come from a trusted source. Returns SCION_ERR_TRC_INVALID if the TRC is malformed or breaks a rule of the PKI.
 */
int scion_trc_parse(const uint8_t *buf, size_t len, struct scion_trc *trc);

void scion_trc_free_members(struct scion_trc *trc);

/*
 * Verifies that a TRC is an update of its predecessor: it follows the rules of a regular or a sensitive update, and the
 * voters of the predecessor voted for it with their signatures. Returns SCION_ERR_TRC_INVALID if it is not.
 */
int scion_trc_verify_update(const struct scion_trc *trc, const struct scion_trc *predecessor);

/*
 * The certificate chain of an AS, which the AS signs its messages of the control plane with.
 */
struct scion_cert_chain {
	// The AS certificate, followed by the CA certificate that issued it
	mbedtls_x509_crt certs;
	// The ISD-AS of the AS certificate
	scion_ia ia;
};

/*
 * Parses a certificate chain from the DER encodings of its AS and CA certificates. Returns SCION_ERR_CERT_INVALID if a
 * certificate is malformed or breaks a rule of the PKI.
 */
int scion_cert_chain_parse(const uint8_t *as_cert, size_t as_cert_len, const uint8_t *ca_cert, size_t ca_cert_len,
	struct scion_cert_chain *chain);

void scion_cert_chain_free_members(struct scion_cert_chain *chain);

/*
 * Verifies a certificate chain against a root certificate of a TRC of the ISD of the chain, at a time. Returns
 * SCION_ERR_CERT_CHAIN_UNVERIFIED if the chain cannot be verified.
 */
int scion_cert_chain_verify(struct scion_cert_chain *chain, struct scion_trc *trc, time_t now);

/*
 * The algorithms of the signatures of the control plane, with the values of proto.crypto.v1.SignatureAlgorithm.
 */
enum scion_signature_algorithm {
	SCION_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA256 = 1,
	SCION_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA384 = 2,
	SCION_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA512 = 3,
};

/*
 * Verifies a signature with the key of the AS certificate of a chain. The signed message is the concatenation of the
 * parts. Returns SCION_ERR_SIGNATURE_INVALID if the signature does not match.
 */
int scion_cert_chain_verify_signature(struct scion_cert_chain *chain, enum scion_signature_algorithm algorithm,
	const struct iovec *parts, size_t num_parts, const uint8_t *signature, size_t signature_len);
