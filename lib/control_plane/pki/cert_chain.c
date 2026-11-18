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
#include <mbedtls/build_info.h>
#include <mbedtls/pk.h>
#include <psa/crypto.h>
#include <string.h>

#include "control_plane/pki/cert.h"
#include "control_plane/pki/cert_chain.h"

int scion_cert_chain_parse(const uint8_t *as_cert, size_t as_cert_len, const uint8_t *ca_cert, size_t ca_cert_len,
	struct scion_cert_chain *chain)
{
	assert(as_cert);
	assert(ca_cert);
	assert(chain);

	(void)memset(chain, 0, sizeof(*chain));
	mbedtls_x509_crt_init(&chain->certs);

	int ret = scion_cert_init();
	if (ret != 0) {
		return ret;
	}

	ret = mbedtls_x509_crt_parse_der(&chain->certs, as_cert, as_cert_len);
	if (ret == 0) {
		ret = mbedtls_x509_crt_parse_der(&chain->certs, ca_cert, ca_cert_len);
	}
	if (ret != 0) {
		scion_cert_chain_free_members(chain);
		return scion_cert_error(ret, SCION_ERR_CERT_INVALID);
	}

	const mbedtls_x509_crt *as = &chain->certs;
	const mbedtls_x509_crt *ca = chain->certs.next;
	bool found;
	if (scion_cert_classify(as) != SCION_CERT_TYPE_AS || scion_cert_classify(ca) != SCION_CERT_TYPE_CA
		|| !scion_cert_covers(ca, scion_cert_time(&as->valid_from), scion_cert_time(&as->valid_to))
		|| scion_cert_find_ia(&as->subject, &found, &chain->ia) != 0 || !found) {
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
	if (verify_ctx->now < scion_cert_time(&crt->valid_from)) {
		*flags |= MBEDTLS_X509_BADCERT_FUTURE;
	}
	if (verify_ctx->now > scion_cert_time(&crt->valid_to)) {
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

	int ret = scion_cert_init();
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

	int ret = scion_cert_init();
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
