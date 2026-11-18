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

#include <assert.h>
#include <mbedtls/asn1.h>
#include <mbedtls/build_info.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <psa/crypto.h>
#include <string.h>

#include "control_plane/cppki.h"

// The OIDs of SCION, see https://docs.scion.org/en/latest/cryptography/certificates.html
#define OID_SCION_IA "\x2b\x06\x01\x04\x01\x83\xb0\x1c\x01\x02\x01"
#define OID_SCION_KP_SENSITIVE "\x2b\x06\x01\x04\x01\x83\xb0\x1c\x01\x03\x01"
#define OID_SCION_KP_REGULAR "\x2b\x06\x01\x04\x01\x83\xb0\x1c\x01\x03\x02"
#define OID_SCION_KP_ROOT "\x2b\x06\x01\x04\x01\x83\xb0\x1c\x01\x03\x03"

// The OIDs of the content types of CMS, see RFC 5652
#define OID_CMS_DATA "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01"
#define OID_CMS_SIGNED_DATA "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"

#define OID_EQUAL(oid, buf) (MBEDTLS_OID_CMP(oid, buf) == 0)

enum cert_type {
	CERT_TYPE_INVALID,
	CERT_TYPE_SENSITIVE,
	CERT_TYPE_REGULAR,
	CERT_TYPE_ROOT,
	CERT_TYPE_CA,
	CERT_TYPE_AS,
};

// The extensions of a certificate that mbedTLS does not expose
struct extensions {
	bool has_basic_constraints;
	bool basic_constraints_critical;
	bool is_ca;
	// The path length constraint, -1 if there is none
	int path_len;
	bool subject_key_id_critical;
	bool authority_key_id_critical;
};

static int crypto_init(void)
{
	return psa_crypto_init() == PSA_SUCCESS ? 0 : SCION_ERR_MEM_ALLOC_FAIL;
}

// The number of days since 1970-01-01 of a date, see https://howardhinnant.github.io/date_algorithms.html
static int64_t days_from_civil(int64_t year, int64_t month, int64_t day)
{
	year -= month <= 2;
	int64_t era = (year >= 0 ? year : year - 399) / 400;
	int64_t year_of_era = year - era * 400;
	int64_t day_of_year = (153 * (month > 2 ? month - 3 : month + 9) + 2) / 5 + day - 1;
	int64_t day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
	return era * 146097 + day_of_era - 719468;
}

static time_t to_time(int64_t year, int64_t month, int64_t day, int64_t hour, int64_t min, int64_t sec)
{
	return (time_t)(days_from_civil(year, month, day) * 86400 + hour * 3600 + min * 60 + sec);
}

static time_t x509_time_to_time(const mbedtls_x509_time *t)
{
	return to_time(t->year, t->mon, t->day, t->hour, t->min, t->sec);
}

// Whether the validity period of a certificate covers a period
static bool covers(const mbedtls_x509_crt *crt, time_t not_before, time_t not_after)
{
	return x509_time_to_time(&crt->valid_from) <= not_before && not_after <= x509_time_to_time(&crt->valid_to);
}

static bool has_ext_key_usage(const mbedtls_x509_crt *crt, const char *oid, size_t oid_len)
{
	for (const mbedtls_x509_sequence *cur = &crt->ext_key_usage; cur != NULL && cur->buf.p != NULL; cur = cur->next) {
		if (cur->buf.len == oid_len && memcmp(cur->buf.p, oid, oid_len) == 0) {
			return true;
		}
	}
	return false;
}

#define HAS_EXT_KEY_USAGE(crt, oid) has_ext_key_usage(crt, oid, MBEDTLS_OID_SIZE(oid))

// Whether a certificate has a key usage extension that allows the usage
static bool has_key_usage(const mbedtls_x509_crt *crt, unsigned int usage)
{
	return mbedtls_x509_crt_has_ext_type(crt, MBEDTLS_X509_EXT_KEY_USAGE)
		   && mbedtls_x509_crt_check_key_usage(crt, usage) == 0;
}

static int parse_basic_constraints(unsigned char *p, const unsigned char *end, struct extensions *ext)
{
	size_t len;
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
		return -1;
	}
	end = p + len;

	int is_ca = 0;
	int ret = mbedtls_asn1_get_bool(&p, end, &is_ca);
	if (ret != 0 && ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
		return -1;
	}
	ext->is_ca = is_ca != 0;

	if (p < end) {
		if (mbedtls_asn1_get_int(&p, end, &ext->path_len) != 0 || ext->path_len < 0) {
			return -1;
		}
	}

	return p == end ? 0 : -1;
}

// Reads the extensions of a certificate that mbedTLS does not expose
static int parse_extensions(const mbedtls_x509_crt *crt, struct extensions *ext)
{
	(void)memset(ext, 0, sizeof(*ext));
	ext->path_len = -1;

	if (crt->v3_ext.p == NULL) {
		return 0;
	}

	// Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
	unsigned char *p = crt->v3_ext.p;
	const unsigned char *end = p + crt->v3_ext.len;
	size_t len;
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
		return -1;
	}
	end = p + len;

	while (p < end) {
		// Extension ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
		if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
			return -1;
		}
		const unsigned char *ext_end = p + len;

		mbedtls_x509_buf oid = { .tag = MBEDTLS_ASN1_OID };
		if (mbedtls_asn1_get_tag(&p, ext_end, &oid.len, MBEDTLS_ASN1_OID) != 0) {
			return -1;
		}
		oid.p = p;
		p += oid.len;

		int critical = 0;
		int ret = mbedtls_asn1_get_bool(&p, ext_end, &critical);
		if (ret != 0 && ret != MBEDTLS_ERR_ASN1_UNEXPECTED_TAG) {
			return -1;
		}

		if (mbedtls_asn1_get_tag(&p, ext_end, &len, MBEDTLS_ASN1_OCTET_STRING) != 0 || p + len != ext_end) {
			return -1;
		}

		if (OID_EQUAL(MBEDTLS_OID_BASIC_CONSTRAINTS, &oid)) {
			ext->has_basic_constraints = true;
			ext->basic_constraints_critical = critical != 0;
			if (parse_basic_constraints(p, ext_end, ext) != 0) {
				return -1;
			}
		} else if (OID_EQUAL(MBEDTLS_OID_SUBJECT_KEY_IDENTIFIER, &oid)) {
			ext->subject_key_id_critical = critical != 0;
		} else if (OID_EQUAL(MBEDTLS_OID_AUTHORITY_KEY_IDENTIFIER, &oid)) {
			ext->authority_key_id_critical = critical != 0;
		}

		p = (unsigned char *)ext_end;
	}

	return 0;
}

// Finds the ISD-AS in a distinguished name. It must be in its canonical form and must not be a wildcard.
static int find_ia(const mbedtls_x509_name *name, bool *found, scion_ia *ia)
{
	*found = false;

	for (const mbedtls_x509_name *cur = name; cur != NULL; cur = cur->next) {
		if (cur->oid.p == NULL || !OID_EQUAL(OID_SCION_IA, &cur->oid)) {
			continue;
		}

		if (scion_ia_parse((const char *)cur->val.p, cur->val.len, ia) != 0 || scion_ia_is_wildcard(*ia)) {
			return -1;
		}

		char canonical[SCION_IA_STRLEN];
		if (scion_ia_str(*ia, canonical, sizeof(canonical)) != 0 || strlen(canonical) != cur->val.len
			|| memcmp(canonical, cur->val.p, cur->val.len) != 0) {
			return -1;
		}

		*found = true;
		return 0;
	}

	return 0;
}

static bool has_ia(const mbedtls_x509_name *name)
{
	bool found;
	scion_ia ia;
	return find_ia(name, &found, &ia) == 0 && found;
}

static bool has_valid_or_no_ia(const mbedtls_x509_name *name)
{
	bool found;
	scion_ia ia;
	return find_ia(name, &found, &ia) == 0;
}

static bool is_scion_signature_algorithm(const mbedtls_x509_buf *sig_oid)
{
	return OID_EQUAL(MBEDTLS_OID_ECDSA_SHA256, sig_oid) || OID_EQUAL(MBEDTLS_OID_ECDSA_SHA384, sig_oid)
		   || OID_EQUAL(MBEDTLS_OID_ECDSA_SHA512, sig_oid);
}

// Whether the authority key ID is absent or the same as the subject key ID, as in a self-signed certificate
static bool has_own_or_no_authority_key_id(const mbedtls_x509_crt *crt)
{
	const mbedtls_x509_buf *authority = &crt->authority_key_id.keyIdentifier;
	return authority->len == 0
		   || (authority->len == crt->subject_key_id.len
			   && memcmp(authority->p, crt->subject_key_id.p, authority->len) == 0);
}

// The rules for all certificates
static bool is_valid_general(const mbedtls_x509_crt *crt, const struct extensions *ext)
{
	return crt->version == 3 && crt->serial.len > 0 && is_scion_signature_algorithm(&crt->sig_oid)
		   && crt->subject_key_id.len > 0 && !ext->subject_key_id_critical && !ext->authority_key_id_critical;
}

// The rules for root and CA certificates
static bool is_valid_ca_common(const mbedtls_x509_crt *crt, const struct extensions *ext, int path_len)
{
	return has_key_usage(crt, MBEDTLS_X509_KU_KEY_CERT_SIGN) && !has_key_usage(crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE)
		   && !HAS_EXT_KEY_USAGE(crt, MBEDTLS_OID_CLIENT_AUTH) && !HAS_EXT_KEY_USAGE(crt, MBEDTLS_OID_SERVER_AUTH)
		   && ext->has_basic_constraints && ext->basic_constraints_critical && ext->is_ca && ext->path_len == path_len
		   && has_ia(&crt->subject) && has_ia(&crt->issuer);
}

// The rules for sensitive and regular voting certificates
static bool is_valid_voting_common(const mbedtls_x509_crt *crt, const struct extensions *ext)
{
	return has_own_or_no_authority_key_id(crt) && !has_key_usage(crt, MBEDTLS_X509_KU_KEY_CERT_SIGN)
		   && !has_key_usage(crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE)
		   && HAS_EXT_KEY_USAGE(crt, MBEDTLS_OID_TIME_STAMPING) && !HAS_EXT_KEY_USAGE(crt, MBEDTLS_OID_CLIENT_AUTH)
		   && !HAS_EXT_KEY_USAGE(crt, MBEDTLS_OID_SERVER_AUTH) && !(ext->has_basic_constraints && ext->is_ca)
		   && has_valid_or_no_ia(&crt->subject) && has_valid_or_no_ia(&crt->issuer);
}

static bool is_valid(const mbedtls_x509_crt *crt, enum cert_type type, const struct extensions *ext)
{
	if (!is_valid_general(crt, ext)) {
		return false;
	}

	switch (type) {
	case CERT_TYPE_SENSITIVE:
		return is_valid_voting_common(crt, ext) && !HAS_EXT_KEY_USAGE(crt, OID_SCION_KP_REGULAR);
	case CERT_TYPE_REGULAR:
		return is_valid_voting_common(crt, ext) && !HAS_EXT_KEY_USAGE(crt, OID_SCION_KP_SENSITIVE);
	case CERT_TYPE_ROOT:
		return is_valid_ca_common(crt, ext, 1) && has_own_or_no_authority_key_id(crt);
	case CERT_TYPE_CA:
		return is_valid_ca_common(crt, ext, 0) && crt->authority_key_id.keyIdentifier.len > 0;
	case CERT_TYPE_AS:
		return has_key_usage(crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE)
			   && !has_key_usage(crt, MBEDTLS_X509_KU_KEY_CERT_SIGN) && !(ext->has_basic_constraints && ext->is_ca)
			   && has_ia(&crt->subject) && has_ia(&crt->issuer) && crt->authority_key_id.keyIdentifier.len > 0
			   && HAS_EXT_KEY_USAGE(crt, MBEDTLS_OID_TIME_STAMPING);
	default:
		return false;
	}
}

// Classifies a certificate by its extended key usages and its key usages, and checks it against the rules of its type.
// Returns CERT_TYPE_INVALID if it breaks a rule.
static enum cert_type classify(const mbedtls_x509_crt *crt)
{
	enum cert_type type;
	if (HAS_EXT_KEY_USAGE(crt, OID_SCION_KP_SENSITIVE)) {
		type = CERT_TYPE_SENSITIVE;
	} else if (HAS_EXT_KEY_USAGE(crt, OID_SCION_KP_REGULAR)) {
		type = CERT_TYPE_REGULAR;
	} else if (HAS_EXT_KEY_USAGE(crt, OID_SCION_KP_ROOT)) {
		type = CERT_TYPE_ROOT;
	} else if (has_key_usage(crt, MBEDTLS_X509_KU_KEY_CERT_SIGN)) {
		type = CERT_TYPE_CA;
	} else if (has_key_usage(crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE)) {
		type = CERT_TYPE_AS;
	} else {
		return CERT_TYPE_INVALID;
	}

	struct extensions ext;
	if (parse_extensions(crt, &ext) != 0 || !is_valid(crt, type, &ext)) {
		return CERT_TYPE_INVALID;
	}

	return type;
}

static int x509_error(int ret, int invalid)
{
	return ret == MBEDTLS_ERR_X509_ALLOC_FAILED ? SCION_ERR_MEM_ALLOC_FAIL : invalid;
}

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

	*time = to_time(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5]);
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
			return x509_error(ret, SCION_ERR_TRC_INVALID);
		}

		// The certificates are for the ISD of the TRC and are valid for as long as the TRC
		bool found;
		scion_ia ia;
		bool for_trc = find_ia(&crt.subject, &found, &ia) == 0 && (!found || scion_ia_get_isd(ia) == trc->isd)
					   && covers(&crt, trc->not_before, trc->not_after);

		enum cert_type type = classify(&crt);
		mbedtls_x509_crt_free(&crt);
		if (!for_trc) {
			return SCION_ERR_TRC_INVALID;
		}

		if (type == CERT_TYPE_SENSITIVE) {
			num_sensitive++;
		} else if (type == CERT_TYPE_REGULAR) {
			num_regular++;
		} else if (type == CERT_TYPE_ROOT) {
			ret = mbedtls_x509_crt_parse_der(&trc->roots, start, len);
			if (ret != 0) {
				return x509_error(ret, SCION_ERR_TRC_INVALID);
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

	int ret = crypto_init();
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

int scion_cert_chain_parse(const uint8_t *as_cert, size_t as_cert_len, const uint8_t *ca_cert, size_t ca_cert_len,
	struct scion_cert_chain *chain)
{
	assert(as_cert);
	assert(ca_cert);
	assert(chain);

	(void)memset(chain, 0, sizeof(*chain));
	mbedtls_x509_crt_init(&chain->certs);

	int ret = crypto_init();
	if (ret != 0) {
		return ret;
	}

	ret = mbedtls_x509_crt_parse_der(&chain->certs, as_cert, as_cert_len);
	if (ret == 0) {
		ret = mbedtls_x509_crt_parse_der(&chain->certs, ca_cert, ca_cert_len);
	}
	if (ret != 0) {
		scion_cert_chain_free_members(chain);
		return x509_error(ret, SCION_ERR_CERT_INVALID);
	}

	const mbedtls_x509_crt *as = &chain->certs;
	const mbedtls_x509_crt *ca = chain->certs.next;
	bool found;
	if (classify(as) != CERT_TYPE_AS || classify(ca) != CERT_TYPE_CA
		|| !covers(ca, x509_time_to_time(&as->valid_from), x509_time_to_time(&as->valid_to))
		|| find_ia(&as->subject, &found, &chain->ia) != 0 || !found) {
		scion_cert_chain_free_members(chain);
		return SCION_ERR_CERT_INVALID;
	}

	return 0;
}

void scion_cert_chain_free_members(struct scion_cert_chain *chain)
{
	if (chain == NULL) {
		return;
	}

	mbedtls_x509_crt_free(&chain->certs);
}

struct verify_context {
	time_t now;
	// The CA certificate of the chain, which must be the certificate between the AS certificate and the root
	const mbedtls_x509_crt *ca;
	// The depth of the root certificate that the chain was verified against
	int root_depth;
};

// Checks the validity of the certificates of a chain at the time of the context instead of the time of the system.
// Called by mbedTLS for each certificate, from the root, which has the greatest depth, to the AS certificate.
static int verify_certificate(void *ctx, mbedtls_x509_crt *crt, int depth, uint32_t *flags)
{
	struct verify_context *verify_ctx = ctx;

	*flags &= ~(uint32_t)(MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE);
	if (verify_ctx->now < x509_time_to_time(&crt->valid_from)) {
		*flags |= MBEDTLS_X509_BADCERT_FUTURE;
	}
	if (verify_ctx->now > x509_time_to_time(&crt->valid_to)) {
		*flags |= MBEDTLS_X509_BADCERT_EXPIRED;
	}

	if (depth == 1 && crt != verify_ctx->ca) {
		*flags |= MBEDTLS_X509_BADCERT_NOT_TRUSTED;
	}
	if (depth > verify_ctx->root_depth) {
		verify_ctx->root_depth = depth;
	}

	return 0;
}

int scion_cert_chain_verify(struct scion_cert_chain *chain, struct scion_trc *trc, time_t now)
{
	assert(chain);
	assert(trc);

	if (scion_ia_get_isd(chain->ia) != trc->isd || trc->roots.raw.p == NULL) {
		return SCION_ERR_CERT_CHAIN_UNVERIFIED;
	}

	int ret = crypto_init();
	if (ret != 0) {
		return ret;
	}

	// The chain is the AS certificate, issued by the CA certificate, issued by a root certificate of the TRC
	struct verify_context ctx = { .now = now, .ca = chain->certs.next, .root_depth = 0 };
	uint32_t flags = 0;
	ret = mbedtls_x509_crt_verify_with_profile(
		&chain->certs, &trc->roots, NULL, &mbedtls_x509_crt_profile_default, NULL, &flags, verify_certificate, &ctx);
	if (ret != 0 || flags != 0 || ctx.root_depth != 2) {
		return SCION_ERR_CERT_CHAIN_UNVERIFIED;
	}

	return 0;
}

int scion_cert_chain_verify_signature(struct scion_cert_chain *chain, enum scion_signature_algorithm algorithm,
	const struct iovec *parts, size_t num_parts, const uint8_t *signature, size_t signature_len)
{
	assert(chain);
	assert(parts || num_parts == 0);
	assert(signature);

	psa_algorithm_t hash_alg;
	mbedtls_md_type_t md_type;
	switch (algorithm) {
	case SCION_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA256:
		hash_alg = PSA_ALG_SHA_256;
		md_type = MBEDTLS_MD_SHA256;
		break;
	case SCION_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA384:
		hash_alg = PSA_ALG_SHA_384;
		md_type = MBEDTLS_MD_SHA384;
		break;
	case SCION_SIGNATURE_ALGORITHM_ECDSA_WITH_SHA512:
		hash_alg = PSA_ALG_SHA_512;
		md_type = MBEDTLS_MD_SHA512;
		break;
	default:
		return SCION_ERR_SIGNATURE_INVALID;
	}

	int ret = crypto_init();
	if (ret != 0) {
		return ret;
	}

	// The signatures of the control plane are ECDSA signatures, the key must not be used for another algorithm
	mbedtls_pk_context *key = &chain->certs.pk;
#if MBEDTLS_VERSION_MAJOR >= 4
	bool is_ecdsa_key = mbedtls_pk_can_do_psa(key, PSA_ALG_ECDSA(hash_alg), PSA_KEY_USAGE_VERIFY_HASH) != 0;
#else
	bool is_ecdsa_key = mbedtls_pk_can_do(key, MBEDTLS_PK_ECKEY) != 0;
#endif
	if (!is_ecdsa_key) {
		return SCION_ERR_SIGNATURE_INVALID;
	}

	uint8_t hash[PSA_HASH_MAX_SIZE];
	size_t hash_len;
	psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
	psa_status_t status = psa_hash_setup(&operation, hash_alg);
	for (size_t i = 0; i < num_parts && status == PSA_SUCCESS; i++) {
		status = psa_hash_update(&operation, parts[i].iov_base, parts[i].iov_len);
	}
	if (status == PSA_SUCCESS) {
		status = psa_hash_finish(&operation, hash, sizeof(hash), &hash_len);
	}
	if (status != PSA_SUCCESS) {
		(void)psa_hash_abort(&operation);
		return SCION_ERR_MEM_ALLOC_FAIL;
	}

	if (mbedtls_pk_verify(key, md_type, hash, hash_len, signature, signature_len) != 0) {
		return SCION_ERR_SIGNATURE_INVALID;
	}

	return 0;
}
