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

#include "bootstrapper.h"
#include "scion/scion.h"
#include "util/endian.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <assert.h>
#include <curl/curl.h>
#include <inttypes.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define INITIAL_HTTP_OUTPUT_BUFFER_SIZE (2 << 11)

#define DISCOVERY_SERVER_DEFAULT_PORT 8041

// MAKE_NV based on nghttp2 - HTTP/2 client tutorial, by Tatsuhiro Tsujikawa
// https://nghttp2.org/documentation/tutorial-client.html
// clang-format off
#define MAKE_NV(NAME, VALUE)                                                                 \
{                                                                                        \
(uint8_t *)NAME, (uint8_t *)VALUE, strlen(NAME), strlen(VALUE), NGHTTP2_NV_FLAG_NONE \
}
// clang-format on

struct naptr_record {
	uint16_t order;
	uint16_t preference;
	u_char flag;
	char target[NS_MAXDNAME];
};

struct ptr_record {
	char target[NS_MAXDNAME];
};

struct srv_record {
	uint16_t priority;
	uint16_t weight;
	uint16_t port;
	char target[NS_MAXDNAME];
};

struct a_record {
	u_char ip[4];
};

struct aaaa_record {
	u_char ip[16];
};

static int fetch_topology_from_discovery_server(struct sockaddr *addr, FILE *topology_stream)
{
	assert(addr->sa_family == AF_INET || addr->sa_family == AF_INET6);
	int ret = 0;

	char url[sizeof("http://[]:65535/topology") + INET6_ADDRSTRLEN];

	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;

		char ip_addr_str[INET_ADDRSTRLEN];
		if (inet_ntop(AF_INET, &in_addr->sin_addr, ip_addr_str, sizeof(ip_addr_str)) == NULL) {
			return -1;
		}

		int print_ret = snprintf(
			url, sizeof(url), "http://%s:%" PRIu16 "/topology", ip_addr_str, ntohs(in_addr->sin_port));
		if (print_ret < 0 || (size_t)print_ret >= sizeof(url)) {
			return -1;
		}
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *in_addr = (struct sockaddr_in6 *)addr;

		char ip_addr_str[INET6_ADDRSTRLEN];
		if (inet_ntop(AF_INET6, &in_addr->sin6_addr, ip_addr_str, sizeof(ip_addr_str)) == NULL) {
			return -1;
		}

		int print_ret = snprintf(
			url, sizeof(url), "http://[%s]:%" PRIu16 "/topology", ip_addr_str, ntohs(in_addr->sin6_port));
		if (print_ret < 0 || (size_t)print_ret >= sizeof(url)) {
			return -1;
		}
	}

	CURLcode curl_code = curl_global_init(CURL_GLOBAL_NOTHING);
	if (curl_code != CURLE_OK) {
		return -1;
	}

	CURL *curl = curl_easy_init();
	if (!curl) {
		ret = -1;
		goto cleanup_curl_global;
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);
	rewind(topology_stream);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, topology_stream);

	CURLcode code = curl_easy_perform(curl);
	if (code != CURLE_OK) {
		ret = -1;
		goto cleanup_curl_easy;
	}

	long response_code;
	code = curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
	if (code != CURLE_OK || response_code != 200) {
		ret = -1;
	}

cleanup_curl_easy:
	curl_easy_cleanup(curl);

cleanup_curl_global:
	curl_global_cleanup();

	return ret;
}

static int query_a_records(res_state resolver, const char *name, struct a_record **records, size_t *records_len)
{
	u_char answer[NS_PACKETSZ];

	int ret = res_nquery(resolver, name, ns_c_in, ns_t_a, answer, sizeof(answer));
	if (ret < 0) {
		return ret;
	}

	ns_msg handle;
	ret = ns_initparse(answer, ret, &handle);
	if (ret != 0) {
		return ret;
	}

	uint16_t msg_count = ns_msg_count(handle, ns_s_an);
	*records = calloc(msg_count, sizeof(**records));
	if (*records == NULL) {
		return -1;
	}

	size_t j = 0;
	for (uint16_t i = 0; i < msg_count; i++) {
		ns_rr rr;
		ret = ns_parserr(&handle, ns_s_an, i, &rr);
		if (ret != 0) {
			continue;
		}

		(void)memcpy(&(*records)[j].ip, ns_rr_rdata(rr), 4);
		j++;
	}

	*records_len = j;

	return 0;
}

static int query_aaaa_records(res_state resolver, const char *name, struct aaaa_record **records, size_t *records_len)
{
	u_char answer[NS_PACKETSZ];

	int ret = res_nquery(resolver, name, ns_c_in, ns_t_aaaa, answer, sizeof(answer));
	if (ret < 0) {
		return ret;
	}

	ns_msg handle;
	ret = ns_initparse(answer, ret, &handle);
	if (ret != 0) {
		return ret;
	}

	uint16_t msg_count = ns_msg_count(handle, ns_s_an);
	*records = calloc(msg_count, sizeof(**records));
	if (*records == NULL) {
		return -1;
	}

	size_t j = 0;
	for (uint16_t i = 0; i < msg_count; i++) {
		ns_rr rr;
		ret = ns_parserr(&handle, ns_s_an, i, &rr);
		if (ret != 0) {
			continue;
		}

		(void)memcpy(&(*records)[j].ip, ns_rr_rdata(rr), 16);
		j++;
	}

	*records_len = j;

	return 0;
}

static int query_ptr_records(res_state resolver, const char *name, struct ptr_record **records, size_t *records_len)
{
	u_char answer[NS_PACKETSZ];

	int ret = res_nquery(resolver, name, ns_c_in, ns_t_ptr, answer, sizeof(answer));
	if (ret < 0) {
		return ret;
	}

	int answerlen = ret;

	ns_msg handle;
	ret = ns_initparse(answer, answerlen, &handle);
	if (ret != 0) {
		return ret;
	}

	uint16_t msg_count = ns_msg_count(handle, ns_s_an);
	*records = calloc(msg_count, sizeof(**records));
	if (*records == NULL) {
		return -1;
	}

	size_t j = 0;
	for (uint16_t i = 0; i < msg_count; i++) {
		ns_rr rr;
		ret = ns_parserr(&handle, ns_s_an, i, &rr);
		if (ret != 0) {
			continue;
		}

		const u_char *comp_target_name = ns_rr_rdata(rr);

		char target_name[NS_MAXDNAME];
		ret = dn_expand(answer, answer + answerlen, comp_target_name, target_name, sizeof(target_name));
		if (ret < 0) {
			continue;
		}

		(void)strcpy((*records)[j].target, target_name);
		j++;
	}

	*records_len = j;

	return 0;
}

static int query_srv_records(res_state resolver, const char *name, struct srv_record **records, size_t *records_len)
{
	u_char answer[NS_PACKETSZ];

	int ret = res_nquery(resolver, name, ns_c_in, ns_t_srv, answer, sizeof(answer));
	if (ret < 0) {
		return ret;
	}

	int answerlen = ret;

	ns_msg handle;
	ret = ns_initparse(answer, answerlen, &handle);
	if (ret != 0) {
		return ret;
	}

	uint16_t msg_count = ns_msg_count(handle, ns_s_an);
	*records = calloc(msg_count, sizeof(**records));
	if (*records == NULL) {
		return -1;
	}

	size_t j = 0;
	for (uint16_t i = 0; i < msg_count; i++) {
		ns_rr rr;
		ret = ns_parserr(&handle, ns_s_an, i, &rr);
		if (ret != 0) {
			continue;
		}

		const u_char *comp_target_name = ns_rr_rdata(rr) + 6;

		char target_name[NS_MAXDNAME];
		ret = dn_expand(answer, answer + answerlen, comp_target_name, target_name, sizeof(target_name));
		if (ret < 0) {
			continue;
		}

		(void)memcpy(&(*records)[j].priority, ns_rr_rdata(rr), sizeof(uint16_t));
		(*records)[j].priority = be16toh((*records)[j].priority);

		(void)memcpy(&(*records)[j].weight, ns_rr_rdata(rr) + 2, sizeof(uint16_t));
		(*records)[j].weight = be16toh((*records)[j].weight);

		(void)memcpy(&(*records)[j].port, ns_rr_rdata(rr) + 4, sizeof(uint16_t));
		(*records)[j].port = be16toh((*records)[j].port);

		(void)strcpy((*records)[j].target, target_name);
		j++;
	}

	*records_len = j;

	return 0;
}

static int query_naptr_records(res_state resolver, const char *name, struct naptr_record **records, size_t *records_len)
{
	u_char answer[NS_PACKETSZ];

	int ret = res_nquery(resolver, name, ns_c_in, ns_t_naptr, answer, sizeof(answer));
	if (ret < 0) {
		return ret;
	}

	int answerlen = ret;

	ns_msg handle;
	ret = ns_initparse(answer, answerlen, &handle);
	if (ret != 0) {
		return ret;
	}

	uint16_t msg_count = ns_msg_count(handle, ns_s_an);
	*records = calloc(msg_count, sizeof(**records));
	if (*records == NULL) {
		return -1;
	}

	size_t j = 0;
	for (uint16_t i = 0; i < msg_count; i++) {
		ns_rr rr;
		ret = ns_parserr(&handle, ns_s_an, i, &rr);
		if (ret != 0) {
			continue;
		}

		const u_char *rdata = ns_rr_rdata(rr);
		// Ignore flags other an 'A' and 'S'
		if (!(rdata[4] == 1 && (rdata[5] == 'A' || rdata[5] == 'S'))) {
			continue;
		}

		// Ignore services other than scion discovery
		if (!(rdata[6] == 20 && memcmp(&rdata[7], "x-sciondiscovery:tcp", 20) == 0)) {
			continue;
		}

		// Regex is not correct
		if (rdata[27] != 0) {
			continue;
		}

		const u_char *comp_target_name = &rdata[28];

		char target_name[NS_MAXDNAME];
		ret = dn_expand(answer, answer + answerlen, comp_target_name, target_name, sizeof(target_name));
		if (ret < 0) {
			continue;
		}

		(void)memcpy(&(*records)[j].order, rdata, sizeof(uint16_t));
		(*records)[j].order = be16toh((*records)[j].order);

		(void)memcpy(&(*records)[j].preference, rdata + 2, sizeof(uint16_t));
		(*records)[j].preference = be16toh((*records)[j].preference);

		(*records)[j].flag = rdata[5];
		(void)strcpy((*records)[j].target, target_name);
		j++;
	}

	*records_len = j;

	return 0;
}

static int resolve_a(res_state resolver, const char *name, uint16_t port, FILE *topology_stream)
{
	struct a_record *records;
	size_t records_len;
	int ret = query_a_records(resolver, name, &records, &records_len);
	if (ret != 0) {
		return ret;
	}

	ret = -1;
	for (size_t i = 0; i < records_len; i++) {
		struct sockaddr_in addr = { 0 };
		addr.sin_family = AF_INET;
		addr.sin_port = htons(port);
		(void)memcpy(&addr.sin_addr, records[i].ip, 4);

		ret = fetch_topology_from_discovery_server((struct sockaddr *)&addr, topology_stream);
		if (ret == 0) {
			goto cleanup_records;
		}
	}

cleanup_records:
	free(records);

	return ret;
}

static int resolve_aaaa(res_state resolver, const char *name, uint16_t port, FILE *topology_stream)
{
	struct aaaa_record *records;
	size_t records_len;
	int ret = query_aaaa_records(resolver, name, &records, &records_len);
	if (ret != 0) {
		goto cleanup_records;
	}

	ret = -1;
	for (size_t i = 0; i < records_len; i++) {
		struct sockaddr_in6 addr = { 0 };
		addr.sin6_family = AF_INET6;
		addr.sin6_port = htons(port);
		(void)memcpy(&addr.sin6_addr, records[i].ip, 16);

		ret = fetch_topology_from_discovery_server((struct sockaddr *)&addr, topology_stream);
		if (ret == 0) {
			goto cleanup_records;
		}
	}

cleanup_records:
	free(records);

	return ret;
}

// Note: This implementation is an approximation of the GO implementation. However, the GO implementation does not
// exactly implement the sort ordering described in RFC2782.
static int compare_srv_records(const void *a, const void *b)
{
	const struct srv_record *record_one = a;
	const struct srv_record *record_two = b;

	if (record_one->priority < record_two->priority) {
		return -1;
	}

	if (record_one->priority > record_two->priority) {
		return 1;
	}

	if (record_one->weight == 0 && record_two->weight == 0) {
		return (rand() % 2) == 0;
	}

	return (rand() % (record_one->weight + record_two->weight)) - record_one->weight;
}

static int resolve_srv(res_state resolver, const char *name, FILE *topology_stream)
{
	struct srv_record *records;
	size_t records_len;
	int ret = query_srv_records(resolver, name, &records, &records_len);
	if (ret != 0) {
		return ret;
	}

	// sort records according to SRV record sorting
	qsort(records, records_len, sizeof(*records), compare_srv_records);

	ret = -1;
	for (size_t i = 0; i < records_len; i++) {
		ret = resolve_aaaa(resolver, records[i].target, records[i].port, topology_stream);
		if (ret == 0) {
			goto cleanup_records;
		}

		ret = resolve_a(resolver, records[i].target, records[i].port, topology_stream);
		if (ret == 0) {
			goto cleanup_records;
		}
	}

cleanup_records:
	free(records);

	return ret;
}

static int resolve_ptr(res_state resolver, const char *name, FILE *topology_stream)
{
	struct ptr_record *records;
	size_t records_len;
	int ret = query_ptr_records(resolver, name, &records, &records_len);
	if (ret != 0) {
		return ret;
	}

	ret = -1;
	for (size_t i = 0; i < records_len; i++) {
		ret = resolve_srv(resolver, records[i].target, topology_stream);
		if (ret == 0) {
			goto cleanup_records;
		}
	}

cleanup_records:
	free(records);

	return ret;
}

static int compare_naptr_records(const void *a, const void *b)
{
	const struct naptr_record *record_one = a;
	const struct naptr_record *record_two = b;

	if (record_one->order < record_two->order) {
		return -1;
	}

	if (record_one->order > record_two->order) {
		return 1;
	}

	return record_one->preference - record_two->preference;
}

static int resolve_naptr(res_state resolver, const char *name, FILE *topology_stream)
{
	struct naptr_record *records;
	size_t records_len;
	int ret = query_naptr_records(resolver, name, &records, &records_len);
	if (ret != 0) {
		return ret;
	}

	// sort records according to NAPTR record sorting
	qsort(records, records_len, sizeof(*records), compare_naptr_records);

	ret = -1;
	for (size_t i = 0; i < records_len; i++) {
		if (records[i].flag == 'A') {
			ret = resolve_aaaa(resolver, records[i].target, DISCOVERY_SERVER_DEFAULT_PORT, topology_stream);
			if (ret == 0) {
				goto cleanup_records;
			}

			ret = resolve_a(resolver, records[i].target, DISCOVERY_SERVER_DEFAULT_PORT, topology_stream);
			if (ret == 0) {
				goto cleanup_records;
			}
		} else if (records[i].flag == 'S') {
			ret = resolve_srv(resolver, records[i].target, topology_stream);
			if (ret == 0) {
				goto cleanup_records;
			}
		}
	}

cleanup_records:
	free(records);

	return ret;
}

static int try_dns_srv(res_state resolver, const char *domain, FILE *topology_stream)
{
	char name[strlen(domain) + sizeof("_sciondiscovery._tcp.")];
	(void)strcpy(name, "_sciondiscovery._tcp.");
	(void)strcat(name, domain);

	return resolve_srv(resolver, name, topology_stream);
}

static int try_dns_sd(res_state resolver, const char *domain, FILE *topology_stream)
{
	char name[strlen(domain) + sizeof("_sciondiscovery._tcp.")];
	(void)strcpy(name, "_sciondiscovery._tcp.");
	(void)strcat(name, domain);

	return resolve_ptr(resolver, name, topology_stream);
}

static int try_dns_naptr(res_state resolver, const char *domain, FILE *topology_stream)
{
	return resolve_naptr(resolver, domain, topology_stream);
}

static int locate_discovery_server_and_fetch_topology(char **topology_buffer, size_t *topology_buffer_len)
{
	struct __res_state resolver;
	int ret = res_ninit(&resolver);
	if (ret != 0) {
		goto cleanup_resolver;
	}

	// Try to extract domain from domain search list
	char *domain = NULL;
	for (int i = 0; resolver.dnsrch[i] != NULL; i++) {
		if (strcmp(resolver.dnsrch[i], "localdomain") != 0) {
			domain = resolver.dnsrch[i];
			break;
		}
	}

	// Search domain unknown, cannot use DNS to search discovery server
	if (domain == NULL) {
		ret = -1;
		goto cleanup_resolver;
	}

	FILE *topology_stream = open_memstream(topology_buffer, topology_buffer_len);
	if (topology_stream == NULL) {
		ret = -1;
		goto cleanup_resolver;
	}

	(void)try_dns_srv;
	ret = try_dns_srv(&resolver, domain, topology_stream);
	if (ret == 0) {
		goto cleanup_stream;
	}

	(void)try_dns_sd;
	ret = try_dns_sd(&resolver, domain, topology_stream);
	if (ret == 0) {
		goto cleanup_stream;
	}

	ret = try_dns_naptr(&resolver, domain, topology_stream);

cleanup_stream:
	(void)fclose(topology_stream);

cleanup_resolver:
	res_nclose(&resolver);

	return ret;
}

int scion_bootstrap(const char *topology_output_path)
{
	char *topology_buffer = NULL;
	size_t topology_buffer_len = 0;

	int ret = locate_discovery_server_and_fetch_topology(&topology_buffer, &topology_buffer_len);
	if (ret != 0) {
		ret = SCION_ERR_BOOTSTRAPPING_FAIL;
		goto cleanup_topology_buffer;
	}

	FILE *topology_output_stream = fopen(topology_output_path, "w");
	if (topology_output_stream == NULL) {
		ret = SCION_ERR_FILE_NOT_FOUND;
		goto cleanup_topology_buffer;
	}

	size_t nwrite = fwrite(topology_buffer, sizeof(*topology_buffer), topology_buffer_len, topology_output_stream);
	if (nwrite != topology_buffer_len) {
		ret = SCION_ERR_BOOTSTRAPPING_FAIL;
	}

	(void)fclose(topology_output_stream);

cleanup_topology_buffer:
	free(topology_buffer);

	return ret;
}
