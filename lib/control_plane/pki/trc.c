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

#include <assert.h>
#include <mbedtls/asn1.h>
#include <string.h>

#include "control_plane/pki/cert.h"
#include "control_plane/pki/trc.h"

// The OIDs of the content types of CMS, see RFC 5652
#define OID_CMS_DATA "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01"
#define OID_CMS_SIGNED_DATA "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"

// Reads a GeneralizedTime of the form YYYYMMDDHHMMSSZ, the only form that DER allows
static int get_generalized_time(unsigned char **p, const unsigned char *end, time_t *time)
{
	size_t len;
	if (mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_GENERALIZED_TIME) != 0 || len != 15 || (*p)[14] != 'Z') {
		return -1;
	}

	int64_t fields[6];
	const size_t widths[6] = { 4, 2, 2, 2, 2, 2 };
	const unsigned char *c = *p;
	for (size_t i = 0; i < 6; i++) {
		fields[i] = 0;
		for (size_t j = 0; j < widths[i]; j++, c++) {
			if (*c < '0' || *c > '9') {
				return -1;
			}
			fields[i] = fields[i] * 10 + (*c - '0');
		}
	}

	if (fields[1] < 1 || fields[1] > 12 || fields[2] < 1 || fields[2] > 31 || fields[3] > 23 || fields[4] > 59
		|| fields[5] > 59) {
		return -1;
	}

	const mbedtls_x509_time t = { .year = (int)fields[0],
		.mon = (int)fields[1],
		.day = (int)fields[2],
		.hour = (int)fields[3],
		.min = (int)fields[4],
		.sec = (int)fields[5] };
	*time = scion_cert_time(&t);
	*p += len;
	return 0;
}

// Skips an element of any type
static int skip(unsigned char **p, const unsigned char *end)
{
	if (end - *p < 1) {
		return -1;
	}
	(*p)++;

	size_t len;
	if (mbedtls_asn1_get_len(p, end, &len) != 0) {
		return -1;
	}
	*p += len;
	return 0;
}

// Reads the certificates of a TRC, keeps its root certificates and checks the rules for the certificates of a TRC
static int parse_trc_certificates(unsigned char *p, const unsigned char *end, struct scion_trc *trc)
{
	size_t num_sensitive = 0;
	size_t num_regular = 0;

	while (p < end) {
		// The certificate with its tag and length
		const unsigned char *start = p;
		if (skip(&p, end) != 0) {
			return SCION_ERR_TRC_INVALID;
		}
		size_t len = (size_t)(p - start);

		mbedtls_x509_crt crt;
		mbedtls_x509_crt_init(&crt);
		int ret = mbedtls_x509_crt_parse_der(&crt, start, len);
		if (ret != 0) {
			mbedtls_x509_crt_free(&crt);
			return scion_cert_error(ret, SCION_ERR_TRC_INVALID);
		}

		// The certificates are for the ISD of the TRC and are valid for as long as the TRC
		bool found;
		scion_ia ia;
		bool for_trc = scion_cert_find_ia(&crt.subject, &found, &ia) == 0
					   && (!found || scion_ia_get_isd(ia) == trc->isd)
					   && scion_cert_covers(&crt, trc->not_before, trc->not_after);

		enum scion_cert_type type = scion_cert_classify(&crt);
		mbedtls_x509_crt_free(&crt);
		if (!for_trc) {
			return SCION_ERR_TRC_INVALID;
		}

		if (type == SCION_CERT_TYPE_SENSITIVE) {
			num_sensitive++;
		} else if (type == SCION_CERT_TYPE_REGULAR) {
			num_regular++;
		} else if (type == SCION_CERT_TYPE_ROOT) {
			ret = mbedtls_x509_crt_parse_der(&trc->roots, start, len);
			if (ret != 0) {
				return scion_cert_error(ret, SCION_ERR_TRC_INVALID);
			}
		} else {
			return SCION_ERR_TRC_INVALID;
		}
	}

	if (num_sensitive < trc->quorum || num_regular < trc->quorum) {
		return SCION_ERR_TRC_INVALID;
	}

	return 0;
}

// Reads the payload of a TRC, see https://docs.scion.org/en/latest/cryptography/trc.html#trc-format
static int parse_trc_payload(unsigned char *p, const unsigned char *end, struct scion_trc *trc)
{
	size_t len;
	int version;
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0 || p + len != end
		|| mbedtls_asn1_get_int(&p, end, &version) != 0 || version != 0) {
		return SCION_ERR_TRC_INVALID;
	}

	// iD ::= SEQUENCE { iSD INTEGER, serialNumber INTEGER, baseNumber INTEGER }
	int isd;
	int serial;
	int base;
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0
		|| mbedtls_asn1_get_int(&p, end, &isd) != 0 || mbedtls_asn1_get_int(&p, end, &serial) != 0
		|| mbedtls_asn1_get_int(&p, end, &base) != 0 || isd < 1 || isd > UINT16_MAX || base < 1 || serial < base) {
		return SCION_ERR_TRC_INVALID;
	}
	trc->isd = (scion_isd)isd;
	trc->serial = (uint64_t)serial;
	trc->base = (uint64_t)base;

	// validity ::= SEQUENCE { notBefore GeneralizedTime, notAfter GeneralizedTime }
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0
		|| get_generalized_time(&p, end, &trc->not_before) != 0 || get_generalized_time(&p, end, &trc->not_after) != 0
		|| trc->not_after <= trc->not_before) {
		return SCION_ERR_TRC_INVALID;
	}

	int grace_period;
	int no_trust_reset;
	if (mbedtls_asn1_get_int(&p, end, &grace_period) != 0 || grace_period < 0
		|| mbedtls_asn1_get_bool(&p, end, &no_trust_reset) != 0) {
		return SCION_ERR_TRC_INVALID;
	}
	trc->grace_period = (uint32_t)grace_period;
	trc->no_trust_reset = no_trust_reset != 0;

	// votes ::= SEQUENCE OF INTEGER
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
		return SCION_ERR_TRC_INVALID;
	}
	size_t votes_len = len;
	p += len;

	// A base TRC has no predecessor to vote on or to stay valid after it
	if (trc->base == trc->serial && (trc->grace_period != 0 || votes_len != 0)) {
		return SCION_ERR_TRC_INVALID;
	}

	int quorum;
	if (mbedtls_asn1_get_int(&p, end, &quorum) != 0 || quorum < 1 || quorum > UINT8_MAX) {
		return SCION_ERR_TRC_INVALID;
	}
	trc->quorum = (uint8_t)quorum;

	// coreASes, authoritativeASes and description
	for (size_t i = 0; i < 3; i++) {
		if (skip(&p, end) != 0) {
			return SCION_ERR_TRC_INVALID;
		}
	}

	// certificates ::= SEQUENCE OF Certificate
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0 || p + len != end) {
		return SCION_ERR_TRC_INVALID;
	}

	return parse_trc_certificates(p, end, trc);
}

int scion_trc_parse(const uint8_t *buf, size_t len, struct scion_trc *trc)
{
	assert(buf);
	assert(trc);

	(void)memset(trc, 0, sizeof(*trc));
	mbedtls_x509_crt_init(&trc->roots);

	int ret = scion_cert_init();
	if (ret != 0) {
		return ret;
	}

	// mbedTLS reads the buffer through non-const pointers, but does not write to it
	unsigned char *p = (unsigned char *)buf;
	const unsigned char *end = buf + len;
	size_t content_len;

	// ContentInfo ::= SEQUENCE { contentType OBJECT IDENTIFIER, content [0] EXPLICIT SignedData }
	mbedtls_x509_buf oid;
	if (mbedtls_asn1_get_tag(&p, end, &content_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0
		|| p + content_len != end || mbedtls_asn1_get_tag(&p, end, &oid.len, MBEDTLS_ASN1_OID) != 0) {
		return SCION_ERR_TRC_INVALID;
	}
	oid.p = p;
	p += oid.len;
	if (!OID_EQUAL(OID_CMS_SIGNED_DATA, &oid)
		|| mbedtls_asn1_get_tag(&p, end, &content_len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED) != 0) {
		return SCION_ERR_TRC_INVALID;
	}

	// SignedData ::= SEQUENCE { version INTEGER, digestAlgorithms SET, encapContentInfo EncapsulatedContentInfo, ... }
	int version;
	if (mbedtls_asn1_get_tag(&p, end, &content_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0
		|| mbedtls_asn1_get_int(&p, end, &version) != 0 || version != 1 || skip(&p, end) != 0) {
		return SCION_ERR_TRC_INVALID;
	}

	// EncapsulatedContentInfo ::= SEQUENCE { eContentType OBJECT IDENTIFIER, eContent [0] EXPLICIT OCTET STRING }
	if (mbedtls_asn1_get_tag(&p, end, &content_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0
		|| mbedtls_asn1_get_tag(&p, end, &oid.len, MBEDTLS_ASN1_OID) != 0) {
		return SCION_ERR_TRC_INVALID;
	}
	oid.p = p;
	p += oid.len;
	if (!OID_EQUAL(OID_CMS_DATA, &oid)
		|| mbedtls_asn1_get_tag(&p, end, &content_len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED) != 0
		|| mbedtls_asn1_get_tag(&p, end, &content_len, MBEDTLS_ASN1_OCTET_STRING) != 0) {
		return SCION_ERR_TRC_INVALID;
	}

	ret = parse_trc_payload(p, p + content_len, trc);
	if (ret != 0) {
		scion_trc_free_members(trc);
	}

	return ret;
}

void scion_trc_free_members(struct scion_trc *trc)
{
	if (trc == NULL) {
		return;
	}

	mbedtls_x509_crt_free(&trc->roots);
}
