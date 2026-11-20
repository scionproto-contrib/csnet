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
#include <dirent.h>
#include <mbedtls/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "control_plane/network.h"
#include "control_plane/network_trcs.h"
#include "proto/control_plane/v1/cppki.pb-c.h"
#include "util/http2_rpc.h"

#define CHAINS_PATH "/proto.control_plane.v1.TrustMaterialService/Chains"
#define INITIAL_RPC_OUTPUT_BUFFER_SIZE 4096

#define TRC_FILE_EXTENSION ".trc"
#define PEM_TRC_HEADER "-----BEGIN TRC-----"
#define PEM_TRC_FOOTER "-----END TRC-----"

// Reads a file into a buffer, which ends with a 0 byte after the content of the file, so it can be read as a string
static int read_file(const char *path, uint8_t **buf, size_t *len)
{
	FILE *file = fopen(path, "rb");
	if (file == NULL) {
		return SCION_ERR_FILE_NOT_FOUND;
	}

	int ret = 0;
	long size;
	if (fseek(file, 0, SEEK_END) != 0 || (size = ftell(file)) < 0 || fseek(file, 0, SEEK_SET) != 0) {
		ret = SCION_ERR_FILE_NOT_FOUND;
		goto close_file;
	}

	*buf = malloc((size_t)size + 1);
	if (*buf == NULL) {
		ret = SCION_ERR_MEM_ALLOC_FAIL;
		goto close_file;
	}

	*len = fread(*buf, 1, (size_t)size, file);
	if (*len != (size_t)size) {
		free(*buf);
		ret = SCION_ERR_FILE_NOT_FOUND;
		goto close_file;
	}
	(*buf)[*len] = 0;

close_file:
	(void)fclose(file);
	return ret;
}

// Parses a TRC in PEM or DER encoding
static int parse_trc_file(const uint8_t *buf, size_t len, struct scion_trc *trc)
{
	if (len < strlen(PEM_TRC_HEADER) || memcmp(buf, PEM_TRC_HEADER, strlen(PEM_TRC_HEADER)) != 0) {
		return scion_trc_parse(buf, len, trc);
	}

	mbedtls_pem_context pem;
	mbedtls_pem_init(&pem);
	size_t pem_len;
	int ret = mbedtls_pem_read_buffer(&pem, PEM_TRC_HEADER, PEM_TRC_FOOTER, buf, NULL, 0, &pem_len);
	if (ret == 0) {
		size_t der_len;
		const unsigned char *der = mbedtls_pem_get_buffer(&pem, &der_len);
		ret = scion_trc_parse(der, der_len, trc);
	} else {
		ret = ret == MBEDTLS_ERR_PEM_ALLOC_FAILED ? SCION_ERR_MEM_ALLOC_FAIL : SCION_ERR_TRC_INVALID;
	}
	mbedtls_pem_free(&pem);

	return ret;
}

static struct scion_trc *find_trc(const struct scion_trc_store *store, scion_isd isd, uint64_t base, uint64_t serial)
{
	for (size_t i = 0; i < store->num_trcs; i++) {
		struct scion_trc *trc = &store->trcs[i];
		if (trc->isd == isd && trc->base == base && trc->serial == serial) {
			return trc;
		}
	}
	return NULL;
}

// Adds a TRC to a store that does not have it yet, which takes over the members of the TRC. Must be called with the
// lock of the store held.
static int add_trc(struct scion_trc_store *store, struct scion_trc *trc)
{
	struct scion_trc *trcs = realloc(store->trcs, (store->num_trcs + 1) * sizeof(*trcs));
	if (trcs == NULL) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}

	trcs[store->num_trcs] = *trc;
	store->trcs = trcs;
	store->num_trcs++;
	return 0;
}

// Creates a store with a first TRC, which takes over the members of the TRC. A store is only created with a TRC, so a
// network has TRCs if it has a store.
static int create_trc_store(struct scion_trc *trc, struct scion_trc_store **store)
{
	struct scion_trc_store *new_store = malloc(sizeof(*new_store));
	if (new_store == NULL) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}

	new_store->trcs = malloc(sizeof(*new_store->trcs));
	if (new_store->trcs == NULL) {
		free(new_store);
		return SCION_ERR_MEM_ALLOC_FAIL;
	}

	if (pthread_mutex_init(&new_store->lock, NULL) != 0) {
		free(new_store->trcs);
		free(new_store);
		return SCION_ERR_MEM_ALLOC_FAIL;
	}
	new_store->trcs[0] = *trc;
	new_store->num_trcs = 1;

	*store = new_store;
	return 0;
}

static int load_trc_file(struct scion_network *net, const char *path)
{
	uint8_t *buf;
	size_t len;
	int ret = read_file(path, &buf, &len);
	if (ret != 0) {
		return ret;
	}

	struct scion_trc trc;
	ret = parse_trc_file(buf, len, &trc);
	free(buf);
	if (ret != 0) {
		return ret;
	}

	// A TRC that is not valid yet cannot have signed anything
	if (time(NULL) < trc.not_before) {
		scion_trc_free_members(&trc);
		return 0;
	}

	if (net->trcs == NULL) {
		ret = create_trc_store(&trc, &net->trcs);
		if (ret != 0) {
			scion_trc_free_members(&trc);
		}
		return ret;
	}

	// A TRC that the network has is not loaded again
	bool added = false;
	(void)pthread_mutex_lock(&net->trcs->lock);
	if (find_trc(net->trcs, trc.isd, trc.base, trc.serial) == NULL) {
		ret = add_trc(net->trcs, &trc);
		added = ret == 0;
	}
	(void)pthread_mutex_unlock(&net->trcs->lock);

	if (!added) {
		scion_trc_free_members(&trc);
	}
	return ret;
}

static bool has_extension(const char *name, const char *extension)
{
	size_t name_len = strlen(name);
	size_t extension_len = strlen(extension);
	return name_len > extension_len && strcmp(name + name_len - extension_len, extension) == 0;
}

int scion_network_load_trcs(struct scion_network *net, const char *dir)
{
	assert(net);
	assert(dir);

	DIR *entries = opendir(dir);
	if (entries == NULL) {
		return SCION_ERR_FILE_NOT_FOUND;
	}

	int ret = 0;
	const struct dirent *entry;
	while (ret == 0 && (entry = readdir(entries)) != NULL) {
		if (!has_extension(entry->d_name, TRC_FILE_EXTENSION)) {
			continue;
		}

		size_t path_len = strlen(dir) + 1 + strlen(entry->d_name) + 1;
		char *path = malloc(path_len);
		if (path == NULL) {
			ret = SCION_ERR_MEM_ALLOC_FAIL;
			break;
		}
		(void)snprintf(path, path_len, "%s/%s", dir, entry->d_name);

		ret = load_trc_file(net, path);
		free(path);
	}

	(void)closedir(entries);
	return ret;
}

void scion_network_free_trcs(struct scion_network *net)
{
	struct scion_trc_store *store = net->trcs;
	if (store == NULL) {
		return;
	}

	for (size_t i = 0; i < store->num_trcs; i++) {
		scion_trc_free_members(&store->trcs[i]);
	}
	free(store->trcs);
	(void)pthread_mutex_destroy(&store->lock);
	free(store);
	net->trcs = NULL;
}

// The TRC of an ISD with the highest base number, and of those the one with the highest serial number
static struct scion_trc *find_latest_trc(const struct scion_trc_store *store, scion_isd isd)
{
	struct scion_trc *latest = NULL;
	for (size_t i = 0; i < store->num_trcs; i++) {
		struct scion_trc *trc = &store->trcs[i];
		if (trc->isd == isd
			&& (latest == NULL || trc->base > latest->base
				|| (trc->base == latest->base && trc->serial > latest->serial))) {
			latest = trc;
		}
	}
	return latest;
}

// Verifies a chain against the active TRCs of a store. Must be called with the lock of the store held.
static int verify_chain(const struct scion_trc_store *store, struct scion_cert_chain *chain, time_t now)
{
	struct scion_trc *latest = find_latest_trc(store, scion_ia_get_isd(chain->ia));
	if (latest == NULL || now < latest->not_before || now > latest->not_after) {
		return SCION_ERR_CERT_CHAIN_UNVERIFIED;
	}

	int ret = scion_cert_chain_verify(chain, latest, now);
	if (ret != SCION_ERR_CERT_CHAIN_UNVERIFIED) {
		return ret;
	}

	// In the grace period of a TRC, the chains that the TRC before it verifies are still valid
	bool in_grace_period = latest->base != latest->serial && now <= latest->not_before + latest->grace_period;
	struct scion_trc *previous = NULL;
	if (in_grace_period) {
		previous = find_trc(store, latest->isd, latest->base, latest->serial - 1);
	}
	if (previous == NULL) {
		return ret;
	}

	return scion_cert_chain_verify(chain, previous, now);
}

bool scion_network_has_trcs(const struct scion_network *net)
{
	assert(net);

	return net->trcs != NULL;
}

int scion_network_verify_chain(const struct scion_network *net, struct scion_cert_chain *chain, time_t now)
{
	assert(net);
	assert(chain);

	struct scion_trc_store *store = net->trcs;
	if (store == NULL) {
		return SCION_ERR_CERT_CHAIN_UNVERIFIED;
	}

	(void)pthread_mutex_lock(&store->lock);
	int ret = verify_chain(store, chain, now);
	(void)pthread_mutex_unlock(&store->lock);
	return ret;
}

// Whether a chain is of an AS and has the subject key ID that a request asked for
static bool is_requested_chain(
	const struct scion_cert_chain *chain, scion_ia ia, const uint8_t *subject_key_id, size_t subject_key_id_len)
{
	const mbedtls_x509_buf *key_id = &chain->certs.subject_key_id;
	return chain->ia == ia && key_id->len == subject_key_id_len
		   && memcmp(key_id->p, subject_key_id, subject_key_id_len) == 0;
}

// Returns the first chain of a response that is the requested one and that the network verifies
static int find_verified_chain(const struct scion_network *net, const Proto__ControlPlane__V1__ChainsResponse *response,
	scion_ia ia, const uint8_t *subject_key_id, size_t subject_key_id_len, time_t now, struct scion_cert_chain *chain)
{
	for (size_t i = 0; i < response->n_chains; i++) {
		const Proto__ControlPlane__V1__Chain *pb_chain = response->chains[i];
		int ret = scion_cert_chain_parse(
			pb_chain->as_cert.data, pb_chain->as_cert.len, pb_chain->ca_cert.data, pb_chain->ca_cert.len, chain);
		if (ret == SCION_ERR_MEM_ALLOC_FAIL) {
			return ret;
		}
		if (ret != 0) {
			continue;
		}

		if (is_requested_chain(chain, ia, subject_key_id, subject_key_id_len)) {
			ret = scion_network_verify_chain(net, chain, now);
			if (ret == 0) {
				return 0;
			}
		}

		scion_cert_chain_free_members(chain);
		if (ret == SCION_ERR_MEM_ALLOC_FAIL) {
			return ret;
		}
	}

	return SCION_ERR_CERT_CHAIN_UNVERIFIED;
}

int scion_network_fetch_chain(const struct scion_network *net, scion_ia ia, const uint8_t *subject_key_id,
	size_t subject_key_id_len, time_t now, struct scion_cert_chain *chain)
{
	assert(net);
	assert(subject_key_id);
	assert(chain);

	Google__Protobuf__Timestamp date = GOOGLE__PROTOBUF__TIMESTAMP__INIT;
	date.seconds = (int64_t)now;
	Proto__ControlPlane__V1__ChainsRequest request = PROTO__CONTROL_PLANE__V1__CHAINS_REQUEST__INIT;
	request.isd_as = ia;
	request.subject_key_id.data = (uint8_t *)subject_key_id;
	request.subject_key_id.len = subject_key_id_len;
	request.date = &date;

	size_t request_len = proto__control_plane__v1__chains_request__get_packed_size(&request);
	uint8_t *request_buf = malloc(request_len);
	if (request_buf == NULL) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}
	(void)proto__control_plane__v1__chains_request__pack(&request, request_buf);

	const struct scion_topology *topology = net->topology;
	http2_rpc_handle hd;
	int ret = http2_rpc_handle_init(
		&hd, (struct sockaddr *)&topology->cs_addr, topology->cs_addr_len, INITIAL_RPC_OUTPUT_BUFFER_SIZE);
	if (ret != 0) {
		goto free_request;
	}

	ret = http2_rpc_request(&hd, CHAINS_PATH, request_buf, request_len);
	if (ret != 0) {
		goto free_handle;
	}

	if (hd.grpc_status_code != 0) {
		ret = http2_rpc_grpc_status_to_error(hd.grpc_status_code);
		goto free_handle;
	}

	Proto__ControlPlane__V1__ChainsResponse *response = proto__control_plane__v1__chains_response__unpack(
		NULL, hd.bytes_written, (const uint8_t *)hd.output_buffer);
	if (response == NULL) {
		ret = SCION_ERR_CONTROL_SERVICE_RESPONSE_INVALID;
		goto free_handle;
	}

	ret = find_verified_chain(net, response, ia, subject_key_id, subject_key_id_len, now, chain);
	proto__control_plane__v1__chains_response__free_unpacked(response, NULL);

free_handle:
	http2_rpc_handle_free(&hd);

free_request:
	free(request_buf);

	return ret;
}
