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

// The certificates of the control-plane PKI of SCION and their rules, which TRCs and certificate chains share.
// https://docs.scion.org/en/latest/cryptography/certificates.html

#pragma once

#include <mbedtls/oid.h>
#include <mbedtls/x509_crt.h>
#include <stdbool.h>
#include <time.h>

#include "common/isd_as.h"

#define OID_EQUAL(oid, buf) (MBEDTLS_OID_CMP(oid, buf) == 0)

enum scion_cert_type {
	SCION_CERT_TYPE_INVALID,
	SCION_CERT_TYPE_SENSITIVE,
	SCION_CERT_TYPE_REGULAR,
	SCION_CERT_TYPE_ROOT,
	SCION_CERT_TYPE_CA,
	SCION_CERT_TYPE_AS,
};

/*
 * Initializes the cryptography of mbedTLS, which a certificate needs before it is parsed or verified.
 */
int scion_cert_init(void);

/*
 * The time of an X.509 time, in seconds since 1970-01-01 UTC.
 */
time_t scion_cert_time(const mbedtls_x509_time *t);

/*
 * Whether the validity period of a certificate covers a period.
 */
bool scion_cert_covers(const mbedtls_x509_crt *crt, time_t not_before, time_t not_after);

/*
 * Finds the ISD-AS in a distinguished name. It must be in its canonical form and must not be a wildcard.
 */
int scion_cert_find_ia(const mbedtls_x509_name *name, bool *found, scion_ia *ia);

/*
 * Classifies a certificate by its extended key usages and its key usages, and checks it against the rules of its type.
 * Returns SCION_CERT_TYPE_INVALID if it breaks a rule.
 */
enum scion_cert_type scion_cert_classify(const mbedtls_x509_crt *crt);

/*
 * The error of a failed parse of a certificate by mbedTLS: SCION_ERR_MEM_ALLOC_FAIL if it ran out of memory, otherwise
 * the error for an invalid certificate.
 */
int scion_cert_error(int ret, int invalid);
