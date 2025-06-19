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

#include <arpa/nameser.h>
#include <assert.h>
#include <curl/curl.h>
#include <inttypes.h>
#include <resolv.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define INITIAL_HTTP_OUTPUT_BUFFER_SIZE (2 << 11)

// MAKE_NV based on nghttp2 - HTTP/2 client tutorial, by Tatsuhiro Tsujikawa
// https://nghttp2.org/documentation/tutorial-client.html
// clang-format off
#define MAKE_NV(NAME, VALUE)                                                                 \
{                                                                                        \
(uint8_t *)NAME, (uint8_t *)VALUE, strlen(NAME), strlen(VALUE), NGHTTP2_NV_FLAG_NONE \
}
// clang-format on

struct naptr_record {
	char target[NS_MAXDNAME];
};

struct ptr_record {
	char target[NS_MAXDNAME];
};

struct srv_record {
	char target[NS_MAXDNAME];
	uint16_t port;
};

struct a_record {
	u_char ip[4];
};

static int query_a_record(res_state state, const char *name, struct a_record *record)
{
	u_char answer[NS_PACKETSZ];

	int ret = res_nquery(state, name, ns_c_in, ns_t_a, answer, sizeof(answer));
	if (ret < 0) {
		return ret;
	}

	ns_msg handle;
	ret = ns_initparse(answer, ret, &handle);
	if (ret != 0) {
		return ret;
	}

	uint16_t msg_count = ns_msg_count(handle, ns_s_an);

	// Return first answer record
	if (msg_count > 0) {
		ns_rr rr;
		ret = ns_parserr(&handle, ns_s_an, 0, &rr);
		if (ret != 0) {
			return ret;
		}

		(void)memcpy(record->ip, ns_rr_rdata(rr), 4);
		return 0;
	}

	return -1;
}

static int query_srv_record(res_state state, const char *name, struct srv_record *record)
{
	u_char answer[NS_PACKETSZ];

	int ret = res_nquery(state, name, ns_c_in, ns_t_srv, answer, sizeof(answer));
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

	// Return first answer record
	if (msg_count > 0) {
		ns_rr rr;
		ret = ns_parserr(&handle, ns_s_an, 0, &rr);
		if (ret != 0) {
			return ret;
		}

		const u_char *comp_target_name = ns_rr_rdata(rr) + 6;

		char target_name[NS_MAXDNAME];
		ret = dn_expand(answer, answer + answerlen, comp_target_name, target_name, sizeof(target_name));
		if (ret < 0) {
			return ret;
		}

		(void)strcpy(record->target, target_name);
		record->port = *(uint16_t *)(ns_rr_rdata(rr) + 4);

		return 0;
	}

	return -1;
}

static int query_ptr_record(res_state state, const char *name, struct ptr_record *record)
{
	u_char answer[NS_PACKETSZ];

	int ret = res_nquery(state, name, ns_c_in, ns_t_ptr, answer, sizeof(answer));
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

	// Return first answer record
	if (msg_count > 0) {
		ns_rr rr;
		ret = ns_parserr(&handle, ns_s_an, 0, &rr);
		if (ret != 0) {
			return ret;
		}

		const u_char *comp_target_name = ns_rr_rdata(rr);

		char target_name[NS_MAXDNAME];
		ret = dn_expand(answer, answer + answerlen, comp_target_name, target_name, sizeof(target_name));
		if (ret < 0) {
			return ret;
		}

		(void)strcpy(record->target, target_name);

		return 0;
	}

	return -1;
}

static int query_naptr_record(res_state state, const char *name, struct naptr_record *record)
{
	u_char answer[NS_PACKETSZ];

	int ret = res_nquery(state, name, ns_c_in, ns_t_naptr, answer, sizeof(answer));
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

	for (uint16_t i = 0; i < msg_count; i++) {
		ns_rr rr;
		ret = ns_parserr(&handle, ns_s_an, i, &rr);
		if (ret != 0) {
			continue;
		}

		const u_char *rdata = ns_rr_rdata(rr);
		// Flag is not correct
		if (!(rdata[4] == 1 && rdata[5] == 'A')) {
			continue;
		}

		// Service is not correct
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

		(void)strcpy(record->target, target_name);

		return 0;
	}

	return -1;
}

static int try_dns_srv(res_state resolver, const char *domain, struct sockaddr *addr, socklen_t *addrlen)
{
	char name[strlen(domain) + 22];
	(void)strcpy(name, "_sciondiscovery._tcp.");
	(void)strcat(name, domain);

	struct srv_record srv_record;
	int ret = query_srv_record(resolver, name, &srv_record);
	if (ret != 0) {
		return ret;
	}

	struct a_record a_record;
	ret = query_a_record(resolver, srv_record.target, &a_record);
	if (ret != 0) {
		return ret;
	}

	assert(*addrlen >= sizeof(struct sockaddr_in));
	*addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
	in_addr->sin_family = AF_INET;
	memcpy(&in_addr->sin_addr, a_record.ip, 4);
	in_addr->sin_port = srv_record.port;

	return 0;
}

static int try_dns_sd(res_state resolver, const char *domain, struct sockaddr *addr, socklen_t *addrlen)
{
	char name[strlen(domain) + 22];
	(void)strcpy(name, "_sciondiscovery._tcp.");
	(void)strcat(name, domain);

	struct ptr_record ptr_record;
	int ret = query_ptr_record(resolver, name, &ptr_record);
	if (ret != 0) {
		return ret;
	}

	struct srv_record srv_record;
	ret = query_srv_record(resolver, ptr_record.target, &srv_record);
	if (ret != 0) {
		return ret;
	}

	struct a_record a_record;
	ret = query_a_record(resolver, srv_record.target, &a_record);
	if (ret != 0) {
		return ret;
	}

	assert(*addrlen >= sizeof(struct sockaddr_in));
	*addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
	in_addr->sin_family = AF_INET;
	memcpy(&in_addr->sin_addr, a_record.ip, 4);
	in_addr->sin_port = srv_record.port;

	return 0;
}

static int try_dns_naptr(res_state resolver, const char *domain, struct sockaddr *addr, socklen_t *addrlen)
{
	struct naptr_record naptr_record;
	int ret = query_naptr_record(resolver, domain, &naptr_record);
	if (ret != 0) {
		return ret;
	}

	struct a_record a_record;
	ret = query_a_record(resolver, naptr_record.target, &a_record);
	if (ret != 0) {
		return ret;
	}

	assert(*addrlen >= sizeof(struct sockaddr_in));
	*addrlen = sizeof(struct sockaddr_in);
	struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;
	in_addr->sin_family = AF_INET;
	memcpy(&in_addr->sin_addr, a_record.ip, 4);
	in_addr->sin_port = htons(8041);

	return 0;
}

static int determine_discovery_server_addr(struct sockaddr *addr, socklen_t *addrlen)
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

	ret = try_dns_srv(&resolver, domain, addr, addrlen);
	if (ret == 0) {
		goto cleanup_resolver;
	}

	ret = try_dns_sd(&resolver, domain, addr, addrlen);
	if (ret == 0) {
		goto cleanup_resolver;
	}

	ret = try_dns_naptr(&resolver, domain, addr, addrlen);

cleanup_resolver:
	res_nclose(&resolver);

	return ret;
}

static int fetch_topology_from_discovery_server(
	struct sockaddr *addr, socklen_t addrlen, char **buffer, size_t *buffer_size)
{
	(void)addrlen;
	int ret = 0;

	assert(addr->sa_family == AF_INET);
	struct sockaddr_in *in_addr = (struct sockaddr_in *)addr;

	char ip_addr_str[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &in_addr->sin_addr, ip_addr_str, INET_ADDRSTRLEN) == NULL) {
		return -1;
	}

	char url[40];
	(void)snprintf(url, sizeof(url), "http://%s:%" PRIu16 "/topology", ip_addr_str, ntohs(in_addr->sin_port));

	CURLcode curl_code = curl_global_init(CURL_GLOBAL_NOTHING);
	if (curl_code != CURLE_OK) {
		return -1;
	}

	CURL *curl = curl_easy_init();
	if (!curl) {
		return -1;
	}

	curl_easy_setopt(curl, CURLOPT_URL, url);

	FILE *stream = open_memstream(buffer, buffer_size);
	if (stream == NULL) {
		ret = -1;
		goto cleanup_curl;
	}

	curl_easy_setopt(curl, CURLOPT_WRITEDATA, stream);

	CURLcode code = curl_easy_perform(curl);
	if (code != CURLE_OK) {
		ret = -1;
	}

	(void)fclose(stream);

cleanup_curl:
	curl_easy_cleanup(curl);
	curl_global_cleanup();

	return ret;
}

int scion_bootstrap(struct scion_topology **topology)
{
	struct sockaddr_storage discovery_server_addr = { 0 };
	socklen_t discovery_server_addr_len = sizeof(discovery_server_addr);

	int ret = determine_discovery_server_addr((struct sockaddr *)&discovery_server_addr, &discovery_server_addr_len);
	if (ret != 0) {
		goto error;
	}

	char *topology_data;
	size_t topology_data_len;
	ret = fetch_topology_from_discovery_server(
		(struct sockaddr *)&discovery_server_addr, discovery_server_addr_len, &topology_data, &topology_data_len);
	if (ret != 0) {
		goto error;
	}

	FILE *topology_stream = fmemopen(topology_data, topology_data_len, "r");
	if (topology_stream == NULL) {
		ret = -1;
		goto cleanup_topology_data;
	}

	ret = scion_topology_from_stream(topology, topology_stream);

	(void)fclose(topology_stream);

cleanup_topology_data:
	free(topology_data);

	if (ret < 0) {
error:
		return SCION_ERR_BOOTSTRAPPING_FAIL;
	}

	return 0;
}
