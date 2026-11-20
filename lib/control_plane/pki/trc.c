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
#include <mbedtls/oid.h>
#include <psa/crypto.h>
#include <stdlib.h>
#include <string.h>

#include "control_plane/pki/cert.h"
#include "control_plane/pki/trc.h"

// The OIDs of the content types of CMS, see RFC 5652
#define OID_CMS_DATA "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x01"
#define OID_CMS_SIGNED_DATA "\x2a\x86\x48\x86\xf7\x0d\x01\x07\x02"
// The OID of the message digest attribute of a CMS signer info, see RFC 5652
#define OID_PKCS9_MESSAGE_DIGEST MBEDTLS_OID_PKCS9 "\x04"

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
			return scion_cert_error(ret, SCION_ERR_TRC_INVALID);
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
		if (scion_cert_find_ia(&crt->subject, &found, &ia) != 0 || (found && scion_ia_get_isd(ia) != trc->isd)
			|| !scion_cert_covers(crt, trc->not_before, trc->not_after)) {
			goto free_certs;
		}

		enum scion_cert_type type = scion_cert_classify(crt);
		if (type == SCION_CERT_TYPE_SENSITIVE) {
			num_sensitive++;
		} else if (type == SCION_CERT_TYPE_REGULAR) {
			num_regular++;
		} else if (type != SCION_CERT_TYPE_ROOT) {
			goto free_certs;
		}

		// A certificate is identified by its issuer and serial number, and among the certificates of its type by its
		// subject
		for (const mbedtls_x509_crt *other = crt->next; other != NULL; other = other->next) {
			if ((equal_bufs(&crt->issuer_raw, &other->issuer_raw) && equal_bufs(&crt->serial, &other->serial))
				|| (equal_bufs(&crt->subject_raw, &other->subject_raw) && scion_cert_classify(other) == type)) {
				goto free_certs;
			}
		}

		if (type == SCION_CERT_TYPE_ROOT) {
			int parse_ret = mbedtls_x509_crt_parse_der(&trc->roots, crt->raw.p, crt->raw.len);
			if (parse_ret != 0) {
				ret = scion_cert_error(parse_ret, SCION_ERR_TRC_INVALID);
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

	int ret = scion_cert_init();
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
	int ret = scion_cert_verify_signature(
		crt, signature_alg->hash_alg, signature_alg->md_type, parts, 2, si->signature.p, si->signature.len);
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

static size_t count_certs(const mbedtls_x509_crt *certs, enum scion_cert_type type)
{
	size_t count = 0;
	for (const mbedtls_x509_crt *crt = certs; crt != NULL; crt = crt->next) {
		count += scion_cert_classify(crt) == type ? 1 : 0;
	}
	return count;
}

// Finds the certificate of a type with the subject of a certificate, -1 if there is none
static int find_by_subject(const mbedtls_x509_crt *certs, enum scion_cert_type type, const mbedtls_x509_crt *crt)
{
	int index = 0;
	for (const mbedtls_x509_crt *cur = certs; cur != NULL; cur = cur->next, index++) {
		if (equal_bufs(&cur->subject_raw, &crt->subject_raw) && scion_cert_classify(cur) == type) {
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

	const enum scion_cert_type types[] = { SCION_CERT_TYPE_SENSITIVE, SCION_CERT_TYPE_ROOT, SCION_CERT_TYPE_REGULAR };
	for (size_t i = 0; i < sizeof(types) / sizeof(types[0]); i++) {
		if (count_certs(&next->certs, types[i]) != count_certs(&pred->certs, types[i])) {
			return SCION_ERR_TRC_INVALID;
		}
	}

	for (const mbedtls_x509_crt *crt = &next->certs; crt != NULL; crt = crt->next) {
		enum scion_cert_type type = scion_cert_classify(crt);
		int pred_index = find_by_subject(&pred->certs, type, crt);
		if (pred_index < 0) {
			return SCION_ERR_TRC_INVALID;
		}

		const mbedtls_x509_crt *pred_crt = cert_at(&pred->certs, (size_t)pred_index);
		if (equal_certs(crt, pred_crt)) {
			continue;
		}

		int ret = 0;
		if (type == SCION_CERT_TYPE_SENSITIVE) {
			ret = SCION_ERR_TRC_INVALID;
		} else if (type == SCION_CERT_TYPE_ROOT) {
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

	int ret = scion_cert_init();
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
	bool is_regular = first_voter != NULL && scion_cert_classify(first_voter) == SCION_CERT_TYPE_REGULAR;
	enum scion_cert_type voter_type = is_regular ? SCION_CERT_TYPE_REGULAR : SCION_CERT_TYPE_SENSITIVE;

	if (is_regular) {
		ret = verify_regular_update(&next, &pred, trc, predecessor);
		if (ret != 0) {
			goto free_parts;
		}
	}

	for (size_t i = 0; i < next.num_votes; i++) {
		const mbedtls_x509_crt *voter = next.votes[i] < 0 ? NULL : cert_at(&pred.certs, (size_t)next.votes[i]);
		if (voter == NULL || voter->raw.p == NULL || scion_cert_classify(voter) != voter_type) {
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
		enum scion_cert_type type = scion_cert_classify(crt);
		if (type != SCION_CERT_TYPE_SENSITIVE && type != SCION_CERT_TYPE_REGULAR) {
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
