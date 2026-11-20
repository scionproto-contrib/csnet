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

#include <mbedtls/asn1.h>
#include <mbedtls/build_info.h>
#include <mbedtls/oid.h>
#include <mbedtls/pk.h>
#include <psa/crypto.h>
#include <string.h>

#include "control_plane/pki/cert.h"

// The OIDs of SCION, see https://docs.scion.org/en/latest/cryptography/certificates.html
#define OID_SCION_IA "\x2b\x06\x01\x04\x01\x83\xb0\x1c\x01\x02\x01"
#define OID_SCION_KP_SENSITIVE "\x2b\x06\x01\x04\x01\x83\xb0\x1c\x01\x03\x01"
#define OID_SCION_KP_REGULAR "\x2b\x06\x01\x04\x01\x83\xb0\x1c\x01\x03\x02"
#define OID_SCION_KP_ROOT "\x2b\x06\x01\x04\x01\x83\xb0\x1c\x01\x03\x03"

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

int scion_cert_init(void)
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

time_t scion_cert_time(const mbedtls_x509_time *t)
{
	return to_time(t->year, t->mon, t->day, t->hour, t->min, t->sec);
}

bool scion_cert_covers(const mbedtls_x509_crt *crt, time_t not_before, time_t not_after)
{
	return scion_cert_time(&crt->valid_from) <= not_before && not_after <= scion_cert_time(&crt->valid_to);
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

int scion_cert_find_ia(const mbedtls_x509_name *name, bool *found, scion_ia *ia)
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
	return scion_cert_find_ia(name, &found, &ia) == 0 && found;
}

static bool has_valid_or_no_ia(const mbedtls_x509_name *name)
{
	bool found;
	scion_ia ia;
	return scion_cert_find_ia(name, &found, &ia) == 0;
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

static bool is_valid(const mbedtls_x509_crt *crt, enum scion_cert_type type, const struct extensions *ext)
{
	if (!is_valid_general(crt, ext)) {
		return false;
	}

	switch (type) {
	case SCION_CERT_TYPE_SENSITIVE:
		return is_valid_voting_common(crt, ext) && !HAS_EXT_KEY_USAGE(crt, OID_SCION_KP_REGULAR);
	case SCION_CERT_TYPE_REGULAR:
		return is_valid_voting_common(crt, ext) && !HAS_EXT_KEY_USAGE(crt, OID_SCION_KP_SENSITIVE);
	case SCION_CERT_TYPE_ROOT:
		return is_valid_ca_common(crt, ext, 1) && has_own_or_no_authority_key_id(crt);
	case SCION_CERT_TYPE_CA:
		return is_valid_ca_common(crt, ext, 0) && crt->authority_key_id.keyIdentifier.len > 0;
	case SCION_CERT_TYPE_AS:
		return has_key_usage(crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE)
			   && !has_key_usage(crt, MBEDTLS_X509_KU_KEY_CERT_SIGN) && !(ext->has_basic_constraints && ext->is_ca)
			   && has_ia(&crt->subject) && has_ia(&crt->issuer) && crt->authority_key_id.keyIdentifier.len > 0
			   && HAS_EXT_KEY_USAGE(crt, MBEDTLS_OID_TIME_STAMPING);
	default:
		return false;
	}
}

enum scion_cert_type scion_cert_classify(const mbedtls_x509_crt *crt)
{
	enum scion_cert_type type;
	if (HAS_EXT_KEY_USAGE(crt, OID_SCION_KP_SENSITIVE)) {
		type = SCION_CERT_TYPE_SENSITIVE;
	} else if (HAS_EXT_KEY_USAGE(crt, OID_SCION_KP_REGULAR)) {
		type = SCION_CERT_TYPE_REGULAR;
	} else if (HAS_EXT_KEY_USAGE(crt, OID_SCION_KP_ROOT)) {
		type = SCION_CERT_TYPE_ROOT;
	} else if (has_key_usage(crt, MBEDTLS_X509_KU_KEY_CERT_SIGN)) {
		type = SCION_CERT_TYPE_CA;
	} else if (has_key_usage(crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE)) {
		type = SCION_CERT_TYPE_AS;
	} else {
		return SCION_CERT_TYPE_INVALID;
	}

	struct extensions ext;
	if (parse_extensions(crt, &ext) != 0 || !is_valid(crt, type, &ext)) {
		return SCION_CERT_TYPE_INVALID;
	}

	return type;
}

int scion_cert_error(int ret, int invalid)
{
	return ret == MBEDTLS_ERR_X509_ALLOC_FAILED ? SCION_ERR_MEM_ALLOC_FAIL : invalid;
}

int scion_cert_verify_signature(const mbedtls_x509_crt *crt, psa_algorithm_t hash_alg, mbedtls_md_type_t md_type,
	const struct iovec *parts, size_t num_parts, const uint8_t *signature, size_t signature_len)
{
	// mbedTLS takes the key as mutable, although verifying with it does not change it
	mbedtls_pk_context *key = (mbedtls_pk_context *)&crt->pk;

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
