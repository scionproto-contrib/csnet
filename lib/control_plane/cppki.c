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
#include <stdlib.h>
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
// The OID of the message digest attribute of a CMS signer info, see RFC 5652
#define OID_PKCS9_MESSAGE_DIGEST MBEDTLS_OID_PKCS9 "\x04"

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

// Parses a sequence of certificates into a chain, in their order
static int parse_certificates(unsigned char *p, const unsigned char *end, mbedtls_x509_crt *certs)
{
	while (p < end) {
		// The certificate with its tag and length
		const unsigned char *start = p;
		if (skip(&p, end) != 0) {
			return SCION_ERR_TRC_INVALID;
		}

		int ret = mbedtls_x509_crt_parse_der(certs, start, (size_t)(p - start));
		if (ret != 0) {
			return x509_error(ret, SCION_ERR_TRC_INVALID);
		}
	}

	return 0;
}

static bool equal_bufs(const mbedtls_x509_buf *a, const mbedtls_x509_buf *b)
{
	return a->len == b->len && memcmp(a->p, b->p, a->len) == 0;
}

// The certificate of a chain at an index, NULL if the chain is shorter
static const mbedtls_x509_crt *cert_at(const mbedtls_x509_crt *certs, size_t index)
{
	const mbedtls_x509_crt *crt = certs;
	for (size_t i = 0; i < index && crt != NULL; i++) {
		crt = crt->next;
	}
	return crt;
}

// Reads the certificates of a TRC, keeps its root certificates and checks the rules for the certificates of a TRC
static int parse_trc_certificates(unsigned char *p, const unsigned char *end, struct scion_trc *trc)
{
	mbedtls_x509_crt certs;
	mbedtls_x509_crt_init(&certs);
	int ret = parse_certificates(p, end, &certs);
	if (ret != 0) {
		goto free_certs;
	}

	size_t num_sensitive = 0;
	size_t num_regular = 0;
	ret = SCION_ERR_TRC_INVALID;
	for (const mbedtls_x509_crt *crt = &certs; crt != NULL && crt->raw.p != NULL; crt = crt->next) {
		// The certificates are for the ISD of the TRC and are valid for as long as the TRC
		bool found;
		scion_ia ia;
		if (find_ia(&crt->subject, &found, &ia) != 0 || (found && scion_ia_get_isd(ia) != trc->isd)
			|| !covers(crt, trc->not_before, trc->not_after)) {
			goto free_certs;
		}

		enum cert_type type = classify(crt);
		if (type == CERT_TYPE_SENSITIVE) {
			num_sensitive++;
		} else if (type == CERT_TYPE_REGULAR) {
			num_regular++;
		} else if (type != CERT_TYPE_ROOT) {
			goto free_certs;
		}

		// A certificate is identified by its issuer and serial number, and among the certificates of its type by its
		// subject
		for (const mbedtls_x509_crt *other = crt->next; other != NULL; other = other->next) {
			if ((equal_bufs(&crt->issuer_raw, &other->issuer_raw) && equal_bufs(&crt->serial, &other->serial))
				|| (equal_bufs(&crt->subject_raw, &other->subject_raw) && classify(other) == type)) {
				goto free_certs;
			}
		}

		if (type == CERT_TYPE_ROOT) {
			int parse_ret = mbedtls_x509_crt_parse_der(&trc->roots, crt->raw.p, crt->raw.len);
			if (parse_ret != 0) {
				ret = x509_error(parse_ret, SCION_ERR_TRC_INVALID);
				goto free_certs;
			}
		}
	}

	if (num_sensitive >= trc->quorum && num_regular >= trc->quorum) {
		ret = 0;
	}

free_certs:
	mbedtls_x509_crt_free(&certs);
	return ret;
}

// The parts of a TRC that a TRC update is verified with, which point into the encoding of the TRC
struct trc_contents {
	// The payload, which the signatures of the TRC sign
	unsigned char *payload;
	size_t payload_len;
	// The content of the votes, a sequence of integers
	unsigned char *votes;
	size_t votes_len;
	// The core ASes and the authoritative ASes, with their tags and lengths
	const unsigned char *core_ases;
	size_t core_ases_len;
	const unsigned char *authoritative_ases;
	size_t authoritative_ases_len;
	// The content of the certificates, a sequence of certificates
	unsigned char *certs;
	size_t certs_len;
	// The content of the signer infos, a set of signer infos
	unsigned char *signer_infos;
	size_t signer_infos_len;
};

// Reads the payload of a TRC, see https://docs.scion.org/en/latest/cryptography/trc.html#trc-format
static int parse_trc_payload(
	unsigned char *p, const unsigned char *end, struct scion_trc *trc, struct trc_contents *contents)
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
	contents->votes = p;
	contents->votes_len = len;
	p += len;

	// A base TRC has no predecessor to vote on or to stay valid after it
	if (trc->base == trc->serial && (trc->grace_period != 0 || contents->votes_len != 0)) {
		return SCION_ERR_TRC_INVALID;
	}

	int quorum;
	if (mbedtls_asn1_get_int(&p, end, &quorum) != 0 || quorum < 1 || quorum > UINT8_MAX) {
		return SCION_ERR_TRC_INVALID;
	}
	trc->quorum = (uint8_t)quorum;

	// coreASes and authoritativeASes, followed by the description
	contents->core_ases = p;
	if (skip(&p, end) != 0) {
		return SCION_ERR_TRC_INVALID;
	}
	contents->core_ases_len = (size_t)(p - contents->core_ases);
	contents->authoritative_ases = p;
	if (skip(&p, end) != 0) {
		return SCION_ERR_TRC_INVALID;
	}
	contents->authoritative_ases_len = (size_t)(p - contents->authoritative_ases);
	if (skip(&p, end) != 0) {
		return SCION_ERR_TRC_INVALID;
	}

	// certificates ::= SEQUENCE OF Certificate
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0 || p + len != end) {
		return SCION_ERR_TRC_INVALID;
	}
	contents->certs = p;
	contents->certs_len = len;

	return parse_trc_certificates(p, end, trc);
}

// Reads a TRC, a CMS signed message, see RFC 5652
static int parse_signed_trc(
	unsigned char *p, const unsigned char *end, struct scion_trc *trc, struct trc_contents *contents)
{
	size_t len;

	// ContentInfo ::= SEQUENCE { contentType OBJECT IDENTIFIER, content [0] EXPLICIT SignedData }
	mbedtls_x509_buf oid;
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0 || p + len != end
		|| mbedtls_asn1_get_tag(&p, end, &oid.len, MBEDTLS_ASN1_OID) != 0) {
		return SCION_ERR_TRC_INVALID;
	}
	oid.p = p;
	p += oid.len;
	if (!OID_EQUAL(OID_CMS_SIGNED_DATA, &oid)
		|| mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED) != 0) {
		return SCION_ERR_TRC_INVALID;
	}

	// SignedData ::= SEQUENCE { version INTEGER, digestAlgorithms SET, encapContentInfo EncapsulatedContentInfo,
	// certificates [0] IMPLICIT OPTIONAL, crls [1] IMPLICIT OPTIONAL, signerInfos SET OF SignerInfo }
	int version;
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0
		|| mbedtls_asn1_get_int(&p, end, &version) != 0 || version != 1 || skip(&p, end) != 0) {
		return SCION_ERR_TRC_INVALID;
	}

	// EncapsulatedContentInfo ::= SEQUENCE { eContentType OBJECT IDENTIFIER, eContent [0] EXPLICIT OCTET STRING }
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0
		|| mbedtls_asn1_get_tag(&p, end, &oid.len, MBEDTLS_ASN1_OID) != 0) {
		return SCION_ERR_TRC_INVALID;
	}
	oid.p = p;
	p += oid.len;
	if (!OID_EQUAL(OID_CMS_DATA, &oid)
		|| mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED) != 0
		|| mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_OCTET_STRING) != 0) {
		return SCION_ERR_TRC_INVALID;
	}
	contents->payload = p;
	contents->payload_len = len;
	p += len;

	// The certificates and CRLs of the signed message are not used, the certificates are in the payload
	while (p < end
		   && (*p == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0)
			   || *p == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1))) {
		if (skip(&p, end) != 0) {
			return SCION_ERR_TRC_INVALID;
		}
	}
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) != 0) {
		return SCION_ERR_TRC_INVALID;
	}
	contents->signer_infos = p;
	contents->signer_infos_len = len;

	return parse_trc_payload(contents->payload, contents->payload + contents->payload_len, trc, contents);
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

	// The TRC keeps its encoding, which a TRC update is verified with
	trc->der = malloc(len);
	if (trc->der == NULL) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}
	(void)memcpy(trc->der, buf, len);
	trc->der_len = len;

	struct trc_contents contents;
	ret = parse_signed_trc(trc->der, trc->der + trc->der_len, trc, &contents);
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
	free(trc->der);
	trc->der = NULL;
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

// Verifies an ECDSA signature over the concatenation of the parts with a key
static int verify_ecdsa(mbedtls_pk_context *key, psa_algorithm_t hash_alg, mbedtls_md_type_t md_type,
	const struct iovec *parts, size_t num_parts, const uint8_t *signature, size_t signature_len)
{
	// The signatures of the control plane are ECDSA signatures, the key must not be used for another algorithm
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

	return verify_ecdsa(&chain->certs.pk, hash_alg, md_type, parts, num_parts, signature, signature_len);
}

// A signer info of a CMS signed message, see RFC 5652, section 5.3
struct signer_info {
	// The signer is identified by the issuer and serial number of its certificate (version 1) or by its subject key ID
	// (version 3)
	int version;
	mbedtls_x509_buf issuer;
	mbedtls_x509_buf serial;
	mbedtls_x509_buf subject_key_id;
	mbedtls_x509_buf digest_algorithm;
	// The signed attributes, with their tag and length, and the message digest among them
	mbedtls_x509_buf signed_attrs;
	mbedtls_x509_buf message_digest;
	mbedtls_x509_buf signature_algorithm;
	mbedtls_x509_buf signature;
};

// Finds the message digest attribute among the signed attributes, of which there must be exactly one
static int find_message_digest(unsigned char *p, const unsigned char *end, mbedtls_x509_buf *message_digest)
{
	bool found = false;
	while (p < end) {
		// Attribute ::= SEQUENCE { attrType OBJECT IDENTIFIER, attrValues SET OF AttributeValue }
		size_t len;
		mbedtls_x509_buf oid;
		if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
			return -1;
		}
		const unsigned char *attr_end = p + len;
		if (mbedtls_asn1_get_tag(&p, attr_end, &oid.len, MBEDTLS_ASN1_OID) != 0) {
			return -1;
		}
		oid.p = p;
		p += oid.len;

		if (OID_EQUAL(OID_PKCS9_MESSAGE_DIGEST, &oid)) {
			if (found || mbedtls_asn1_get_tag(&p, attr_end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET) != 0
				|| mbedtls_asn1_get_tag(&p, attr_end, &message_digest->len, MBEDTLS_ASN1_OCTET_STRING) != 0
				|| p + message_digest->len != attr_end) {
				return -1;
			}
			message_digest->p = p;
			found = true;
		}
		p = (unsigned char *)attr_end;
	}

	return found ? 0 : -1;
}

// SignerInfo ::= SEQUENCE { version CMSVersion, sid SignerIdentifier, digestAlgorithm DigestAlgorithmIdentifier,
// signedAttrs [0] IMPLICIT SignedAttributes, signatureAlgorithm SignatureAlgorithmIdentifier,
// signature SignatureValue, unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
static int parse_signer_info(unsigned char **p, const unsigned char *end, struct signer_info *si)
{
	(void)memset(si, 0, sizeof(*si));

	size_t len;
	if (mbedtls_asn1_get_tag(p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
		return -1;
	}
	const unsigned char *si_end = *p + len;

	if (mbedtls_asn1_get_int(p, si_end, &si->version) != 0) {
		return -1;
	}
	if (si->version == 1) {
		// IssuerAndSerialNumber ::= SEQUENCE { issuer Name, serialNumber CertificateSerialNumber }
		if (mbedtls_asn1_get_tag(p, si_end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
			return -1;
		}
		const unsigned char *sid_end = *p + len;
		si->issuer.p = *p;
		if (skip(p, sid_end) != 0) {
			return -1;
		}
		si->issuer.len = (size_t)(*p - si->issuer.p);
		if (mbedtls_asn1_get_tag(p, sid_end, &si->serial.len, MBEDTLS_ASN1_INTEGER) != 0
			|| *p + si->serial.len != sid_end) {
			return -1;
		}
		si->serial.p = *p;
		*p += si->serial.len;
	} else if (si->version == 3) {
		// SubjectKeyIdentifier [0] IMPLICIT OCTET STRING
		if (mbedtls_asn1_get_tag(p, si_end, &si->subject_key_id.len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | 0) != 0) {
			return -1;
		}
		si->subject_key_id.p = *p;
		*p += si->subject_key_id.len;
	} else {
		return -1;
	}

	mbedtls_x509_buf params;
	if (mbedtls_asn1_get_alg(p, si_end, &si->digest_algorithm, &params) != 0) {
		return -1;
	}

	// The signature signs the signed attributes, which hold the message digest of the content
	si->signed_attrs.p = *p;
	if (mbedtls_asn1_get_tag(p, si_end, &len, MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0) != 0
		|| find_message_digest(*p, *p + len, &si->message_digest) != 0) {
		return -1;
	}
	*p += len;
	si->signed_attrs.len = (size_t)(*p - si->signed_attrs.p);

	if (mbedtls_asn1_get_alg(p, si_end, &si->signature_algorithm, &params) != 0
		|| mbedtls_asn1_get_tag(p, si_end, &si->signature.len, MBEDTLS_ASN1_OCTET_STRING) != 0) {
		return -1;
	}
	si->signature.p = *p;

	// The unsigned attributes are not used
	*p = (unsigned char *)si_end;
	return 0;
}

static bool is_signer(const struct signer_info *si, const mbedtls_x509_crt *crt)
{
	if (si->version == 1) {
		return equal_bufs(&si->issuer, &crt->issuer_raw) && equal_bufs(&si->serial, &crt->serial);
	}
	return equal_bufs(&si->subject_key_id, &crt->subject_key_id);
}

struct hash_algorithm {
	const char *digest_oid;
	size_t digest_oid_len;
	const char *ecdsa_oid;
	size_t ecdsa_oid_len;
	psa_algorithm_t hash_alg;
	mbedtls_md_type_t md_type;
};

#define HASH_ALGORITHM(digest_oid, ecdsa_oid, hash_alg, md_type) \
	{ digest_oid, MBEDTLS_OID_SIZE(digest_oid), ecdsa_oid, MBEDTLS_OID_SIZE(ecdsa_oid), hash_alg, md_type }

static const struct hash_algorithm hash_algorithms[] = {
	HASH_ALGORITHM(MBEDTLS_OID_DIGEST_ALG_SHA256, MBEDTLS_OID_ECDSA_SHA256, PSA_ALG_SHA_256, MBEDTLS_MD_SHA256),
	HASH_ALGORITHM(MBEDTLS_OID_DIGEST_ALG_SHA384, MBEDTLS_OID_ECDSA_SHA384, PSA_ALG_SHA_384, MBEDTLS_MD_SHA384),
	HASH_ALGORITHM(MBEDTLS_OID_DIGEST_ALG_SHA512, MBEDTLS_OID_ECDSA_SHA512, PSA_ALG_SHA_512, MBEDTLS_MD_SHA512),
};

// The hash algorithm of a digest algorithm, or of an ECDSA signature algorithm, NULL if it is not supported
static const struct hash_algorithm *find_hash_algorithm(const mbedtls_x509_buf *oid, bool ecdsa)
{
	for (size_t i = 0; i < sizeof(hash_algorithms) / sizeof(hash_algorithms[0]); i++) {
		const struct hash_algorithm *alg = &hash_algorithms[i];
		const char *alg_oid = ecdsa ? alg->ecdsa_oid : alg->digest_oid;
		size_t alg_oid_len = ecdsa ? alg->ecdsa_oid_len : alg->digest_oid_len;
		if (oid->len == alg_oid_len && memcmp(oid->p, alg_oid, alg_oid_len) == 0) {
			return alg;
		}
	}
	return NULL;
}

// Verifies the signature of a signer info over a payload with the key of a certificate
static int verify_signer_info(
	const struct signer_info *si, const mbedtls_x509_crt *crt, const unsigned char *payload, size_t payload_len)
{
	const struct hash_algorithm *digest_alg = find_hash_algorithm(&si->digest_algorithm, false);
	const struct hash_algorithm *signature_alg = find_hash_algorithm(&si->signature_algorithm, true);
	if (digest_alg == NULL || signature_alg == NULL) {
		return SCION_ERR_TRC_INVALID;
	}

	uint8_t digest[PSA_HASH_MAX_SIZE];
	size_t digest_len;
	psa_status_t status = psa_hash_compute(
		digest_alg->hash_alg, payload, payload_len, digest, sizeof(digest), &digest_len);
	if (status != PSA_SUCCESS) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}
	if (digest_len != si->message_digest.len || memcmp(digest, si->message_digest.p, digest_len) != 0) {
		return SCION_ERR_TRC_INVALID;
	}

	// The signed attributes are signed with the tag of a SET instead of their implicit tag
	uint8_t set_tag = MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SET;
	struct iovec parts[] = { { .iov_base = &set_tag, .iov_len = 1 },
		{ .iov_base = si->signed_attrs.p + 1, .iov_len = si->signed_attrs.len - 1 } };
	int ret = verify_ecdsa((mbedtls_pk_context *)&crt->pk, signature_alg->hash_alg, signature_alg->md_type, parts, 2,
		si->signature.p, si->signature.len);
	return ret == SCION_ERR_SIGNATURE_INVALID ? SCION_ERR_TRC_INVALID : ret;
}

// Verifies that a certificate signed a TRC: a signer info of the TRC is of the certificate, and all of them verify
static int verify_signed_by(const struct trc_contents *contents, const mbedtls_x509_crt *crt)
{
	bool signed_by = false;
	unsigned char *p = contents->signer_infos;
	const unsigned char *end = p + contents->signer_infos_len;
	while (p < end) {
		struct signer_info si;
		if (parse_signer_info(&p, end, &si) != 0) {
			return SCION_ERR_TRC_INVALID;
		}
		if (!is_signer(&si, crt)) {
			continue;
		}

		int ret = verify_signer_info(&si, crt, contents->payload, contents->payload_len);
		if (ret != 0) {
			return ret;
		}
		signed_by = true;
	}

	return signed_by ? 0 : SCION_ERR_TRC_INVALID;
}

// The parsed parts of a TRC that a TRC update is verified with
struct trc_update_part {
	struct trc_contents contents;
	mbedtls_x509_crt certs;
	// The indices of the certificates of the predecessor that voted for the TRC
	int *votes;
	size_t num_votes;
};

static void init_trc_update_part(struct trc_update_part *part)
{
	(void)memset(part, 0, sizeof(*part));
	mbedtls_x509_crt_init(&part->certs);
}

static int parse_trc_update_part(const struct scion_trc *trc, struct trc_update_part *part)
{
	// The parts of the TRC that it does not keep are read from its encoding again, which was parsed before
	struct scion_trc parsed;
	(void)memset(&parsed, 0, sizeof(parsed));
	mbedtls_x509_crt_init(&parsed.roots);
	int ret = parse_signed_trc(trc->der, trc->der + trc->der_len, &parsed, &part->contents);
	mbedtls_x509_crt_free(&parsed.roots);
	if (ret != 0) {
		return ret;
	}

	ret = parse_certificates(part->contents.certs, part->contents.certs + part->contents.certs_len, &part->certs);
	if (ret != 0) {
		return ret;
	}

	// votes ::= SEQUENCE OF INTEGER, each the index of a certificate in the predecessor
	unsigned char *p = part->contents.votes;
	const unsigned char *end = p + part->contents.votes_len;
	while (p < end) {
		int *votes = realloc(part->votes, (part->num_votes + 1) * sizeof(*votes));
		if (votes == NULL) {
			return SCION_ERR_MEM_ALLOC_FAIL;
		}
		part->votes = votes;
		if (mbedtls_asn1_get_int(&p, end, &part->votes[part->num_votes]) != 0) {
			return SCION_ERR_TRC_INVALID;
		}
		for (size_t i = 0; i < part->num_votes; i++) {
			if (part->votes[i] == part->votes[part->num_votes]) {
				return SCION_ERR_TRC_INVALID;
			}
		}
		part->num_votes++;
	}

	return 0;
}

static void free_trc_update_part(struct trc_update_part *part)
{
	mbedtls_x509_crt_free(&part->certs);
	free(part->votes);
}

static size_t count_certs(const mbedtls_x509_crt *certs, enum cert_type type)
{
	size_t count = 0;
	for (const mbedtls_x509_crt *crt = certs; crt != NULL; crt = crt->next) {
		count += classify(crt) == type ? 1 : 0;
	}
	return count;
}

// Finds the certificate of a type with the subject of a certificate, -1 if there is none
static int find_by_subject(const mbedtls_x509_crt *certs, enum cert_type type, const mbedtls_x509_crt *crt)
{
	int index = 0;
	for (const mbedtls_x509_crt *cur = certs; cur != NULL; cur = cur->next, index++) {
		if (equal_bufs(&cur->subject_raw, &crt->subject_raw) && classify(cur) == type) {
			return index;
		}
	}
	return -1;
}

static bool equal_certs(const mbedtls_x509_crt *a, const mbedtls_x509_crt *b)
{
	return equal_bufs(&a->raw, &b->raw);
}

/*
 * Checks the rules of a regular update: it changes only the certificates of the root and of the regular voters, which
 * must vote or acknowledge the update with the certificate of the predecessor, and the votes are cast by regular
 * voters.
 */
static int verify_regular_update(const struct trc_update_part *next, const struct trc_update_part *pred,
	const struct scion_trc *trc, const struct scion_trc *predecessor)
{
	if (trc->quorum != predecessor->quorum || next->contents.core_ases_len != pred->contents.core_ases_len
		|| memcmp(next->contents.core_ases, pred->contents.core_ases, pred->contents.core_ases_len) != 0
		|| next->contents.authoritative_ases_len != pred->contents.authoritative_ases_len
		|| memcmp(next->contents.authoritative_ases, pred->contents.authoritative_ases,
			   pred->contents.authoritative_ases_len)
			   != 0) {
		return SCION_ERR_TRC_INVALID;
	}

	const enum cert_type types[] = { CERT_TYPE_SENSITIVE, CERT_TYPE_ROOT, CERT_TYPE_REGULAR };
	for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
		if (count_certs(&next->certs, types[i]) != count_certs(&pred->certs, types[i])) {
			return SCION_ERR_TRC_INVALID;
		}
	}

	for (const mbedtls_x509_crt *crt = &next->certs; crt != NULL; crt = crt->next) {
		enum cert_type type = classify(crt);
		int pred_index = find_by_subject(&pred->certs, type, crt);
		if (pred_index < 0) {
			return SCION_ERR_TRC_INVALID;
		}

		const mbedtls_x509_crt *pred_crt = cert_at(&pred->certs, (size_t)pred_index);
		if (equal_certs(crt, pred_crt)) {
			continue;
		}

		int ret = 0;
		if (type == CERT_TYPE_SENSITIVE) {
			ret = SCION_ERR_TRC_INVALID;
		} else if (type == CERT_TYPE_ROOT) {
			// A changed root certificate acknowledges the update with its certificate of the predecessor
			ret = verify_signed_by(&next->contents, pred_crt);
		} else {
			// A changed regular voting certificate votes with its certificate of the predecessor
			bool voted = false;
			for (size_t j = 0; j < next->num_votes; j++) {
				voted = voted || next->votes[j] == pred_index;
			}
			ret = voted ? 0 : SCION_ERR_TRC_INVALID;
		}
		if (ret != 0) {
			return ret;
		}
	}

	return 0;
}

int scion_trc_verify_update(const struct scion_trc *trc, const struct scion_trc *predecessor)
{
	assert(trc);
	assert(predecessor);

	if (trc->isd != predecessor->isd || trc->base != predecessor->base || trc->serial != predecessor->serial + 1
		|| trc->no_trust_reset != predecessor->no_trust_reset) {
		return SCION_ERR_TRC_INVALID;
	}

	int ret = crypto_init();
	if (ret != 0) {
		return ret;
	}

	struct trc_update_part next;
	struct trc_update_part pred;
	init_trc_update_part(&next);
	init_trc_update_part(&pred);
	ret = parse_trc_update_part(trc, &next);
	if (ret == 0) {
		ret = parse_trc_update_part(predecessor, &pred);
	}
	if (ret != 0) {
		goto free_parts;
	}

	ret = SCION_ERR_TRC_INVALID;
	if (next.num_votes < predecessor->quorum) {
		goto free_parts;
	}

	// The votes of a regular update are cast by regular voters, the ones of a sensitive update by sensitive voters
	const mbedtls_x509_crt *first_voter = cert_at(&pred.certs, (size_t)next.votes[0]);
	bool is_regular = first_voter != NULL && classify(first_voter) == CERT_TYPE_REGULAR;
	enum cert_type voter_type = is_regular ? CERT_TYPE_REGULAR : CERT_TYPE_SENSITIVE;

	if (is_regular) {
		ret = verify_regular_update(&next, &pred, trc, predecessor);
		if (ret != 0) {
			goto free_parts;
		}
	}

	for (size_t i = 0; i < next.num_votes; i++) {
		const mbedtls_x509_crt *voter = next.votes[i] < 0 ? NULL : cert_at(&pred.certs, (size_t)next.votes[i]);
		if (voter == NULL || voter->raw.p == NULL || classify(voter) != voter_type) {
			ret = SCION_ERR_TRC_INVALID;
			goto free_parts;
		}
		ret = verify_signed_by(&next.contents, voter);
		if (ret != 0) {
			goto free_parts;
		}
	}

	// The voters that the predecessor does not have prove that they hold their keys
	for (const mbedtls_x509_crt *crt = &next.certs; crt != NULL; crt = crt->next) {
		enum cert_type type = classify(crt);
		if (type != CERT_TYPE_SENSITIVE && type != CERT_TYPE_REGULAR) {
			continue;
		}
		int pred_index = find_by_subject(&pred.certs, type, crt);
		if (pred_index >= 0 && equal_certs(crt, cert_at(&pred.certs, (size_t)pred_index))) {
			continue;
		}
		ret = verify_signed_by(&next.contents, crt);
		if (ret != 0) {
			goto free_parts;
		}
	}

	ret = 0;

free_parts:
	free_trc_update_part(&next);
	free_trc_update_part(&pred);
	return ret;
}
