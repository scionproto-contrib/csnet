// Copyright 2024 ETH Zurich
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#define JSMN_STATIC
#include "util/jsmn.h"

#include "common/isd_as.h"
#include "control_plane/topology.h"
#include "data_plane/path.h"

#if defined(__APPLE__)
static void *scion_memrchr(const void *s, int c, size_t n)
{
	if (s == NULL) {
		return NULL;
	}

	const unsigned char *t = s;
	while (n > 0) {
		n--;
		if (t[n] == (unsigned char)c) {
			return (void *)&t[n];
		}
	}

	return NULL;
}
#else
#define scion_memrchr memrchr
#endif

#define MAXTOK 1024

void scion_free_border_router(struct scion_border_router *br)
{
	if (br == NULL) {
		return;
	}
	if (br->ifids != NULL) {
		free(br->ifids);
	}
	free(br);
}

void scion_topology_free(struct scion_topology *topo)
{
	if (topo == NULL) {
		return;
	}
	if (topo->border_routers != NULL) {
		scion_list_free(topo->border_routers);
		topo->border_routers = NULL;
	}
	free(topo);
}

/* ---------- helpers ---------- */

static int json_eq(const char *json, const jsmntok_t *tok, const char *s)
{
	size_t len = strlen(s);

	return tok->type == JSMN_STRING && (size_t)(tok->end - tok->start) == len
		   && strncmp(json + tok->start, s, len) == 0;
}

/* skip token including children */
static int tok_skip(jsmntok_t *tok, int i)
{
	int j = i + 1;

	if (tok[i].type == JSMN_OBJECT) {
		for (int n = 0; n < tok[i].size * 2; n++)
			j = tok_skip(tok, j);
	} else if (tok[i].type == JSMN_ARRAY) {
		for (int n = 0; n < tok[i].size; n++)
			j = tok_skip(tok, j);
	}

	return j;
}

/* find value token for key inside object */
static int object_find(const char *json, jsmntok_t *tok, int obj, const char *key)
{
	if (tok[obj].type != JSMN_OBJECT)
		return -1;

	int i = obj + 1;

	for (int n = 0; n < tok[obj].size; n++) {
		int k = i;
		int v = i + 1;

		if (json_eq(json, &tok[k], key))
			return v;

		i = tok_skip(tok, v);
	}

	return -1;
}

/* copy token into buffer */
static void tok_str(const char *json, jsmntok_t *tok, int idx, char *dst, size_t cap)
{
	if (idx < 0) {
		dst[0] = 0;
		return;
	}

	int len = tok[idx].end - tok[idx].start;

	if ((size_t)len >= cap)
		len = (int)cap - 1;

	memcpy(dst, json + tok[idx].start, (size_t)len);
	dst[len] = 0;
}

static int array_contains(const char *json, jsmntok_t *tok, int arr_idx, const char *wanted)
{
	if (arr_idx < 0)
		return 0;

	if (tok[arr_idx].type != JSMN_ARRAY)
		return 0;

	int i = arr_idx + 1;

	for (int n = 0; n < tok[arr_idx].size; n++) {
		if (json_eq(json, &tok[i], wanted))
			return 1;

		i = tok_skip(tok, i);
	}

	return 0;
}

/* ---------- parsing ---------- */

static int parse_address(char *buff, size_t buff_len, struct sockaddr_storage *addr, socklen_t *addr_len)
{
	// Find last colon
	char *colon_ptr = scion_memrchr(buff, ':', buff_len);
	if (colon_ptr == NULL) {
		return SCION_ERR_TOPOLOGY_INVALID;
	}

	// IP
	size_t ip_len = (size_t)(colon_ptr - buff);
	if (buff_len == 0) {
		return SCION_ERR_TOPOLOGY_INVALID;
	}

	uint16_t *port_storage;
	if (memchr(buff, '[', ip_len) != NULL && memchr(buff, ']', ip_len) != NULL) {
		// IPv6, which was "[IP]:Port", do not copy "[" and "]"
		ip_len -= 2;

		char ip[ip_len + 1];
		(void)memcpy(ip, buff + 1, ip_len);
		ip[ip_len] = 0x00;

		// Validate IP
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr;
		addr_in6->sin6_family = AF_INET6;
		*addr_len = sizeof(*addr_in6);
		if (inet_pton(AF_INET6, ip, &addr_in6->sin6_addr) != 1) {
			return SCION_ERR_TOPOLOGY_INVALID;
		}

		port_storage = &addr_in6->sin6_port;
	} else {
		char ip[ip_len + 1];
		(void)memcpy(ip, buff, ip_len);
		ip[ip_len] = 0x00;

		// Validate IP
		struct sockaddr_in *addr_in = (struct sockaddr_in *)addr;
		addr_in->sin_family = AF_INET;
		*addr_len = sizeof(*addr_in);
		if (inet_pton(AF_INET, ip, &addr_in->sin_addr) != 1) {
			return SCION_ERR_TOPOLOGY_INVALID;
		}

		port_storage = &addr_in->sin_port;
	}

	// Port
	size_t port_len = (size_t)((ssize_t)buff_len - (colon_ptr + 1 - buff));
	if (port_len < 1) {
		return SCION_ERR_TOPOLOGY_INVALID;
	}
	char port[port_len + 1];
	(void)memcpy(port, colon_ptr + 1, port_len);
	port[port_len] = 0x00;
	*port_storage = htons((uint16_t)strtoul(port, NULL, 10));

	return 0;
}

static int parse_interfaces(const char *json, jsmntok_t *tok, int interfaces_idx, struct scion_border_router *br)
{
	if (interfaces_idx < 0)
		return SCION_ERR_TOPOLOGY_INVALID;

	int i = interfaces_idx + 1;
	br->ifids = malloc((long unsigned int)tok[interfaces_idx].size * sizeof(scion_ifid));
	br->ifid_len = (size_t)tok[interfaces_idx].size;
	for (int n = 0; n < tok[interfaces_idx].size; n++) {
		char ifid[32];
		tok_str(json, tok, i, ifid, sizeof(ifid));

		int ifobj = i + 1;

		// extract and add interface number of current border router
		br->ifids[n] = strtoul(ifid, NULL, 10);

		i = tok_skip(tok, ifobj);
	}
	return EXIT_SUCCESS;
}

static int parse_control_service(const char *json, jsmntok_t *tok, int cs_idx, struct scion_topology *topo)
{
	if (cs_idx < 0)
		return SCION_ERR_TOPOLOGY_INVALID;

	if (tok[cs_idx].type != JSMN_OBJECT)
		return SCION_ERR_TOPOLOGY_INVALID;

	int i = cs_idx + 1;
	for (int n = 0; n < tok[cs_idx].size; n++) {
		// control service instance name
		char name[64];
		tok_str(json, tok, i, name, sizeof(name));

		int obj = i + 1;

		// extract and parse control service address
		char addr[64];
		tok_str(json, tok, object_find(json, tok, obj, "addr"), addr, sizeof(addr));
		size_t addrStrLen = strnlen(addr, 64);
		parse_address(addr, addrStrLen, &topo->cs_addr, &topo->cs_addr_len);

		i = tok_skip(tok, obj);
		// JSON structure would allow multiple control services, but currently only 1 is supported.
		return EXIT_SUCCESS;
	}
	return SCION_ERR_TOPOLOGY_INVALID;
}

static int parse_border_routers(const char *json, jsmntok_t *tok, int br_idx, struct scion_topology *topo)
{
	if (br_idx < 0)
		return SCION_ERR_TOPOLOGY_INVALID;

	int i = br_idx + 1;
	for (int n = 0; n < tok[br_idx].size; n++) {
		// border router instance name
		char name[64];
		tok_str(json, tok, i, name, sizeof(name));

		int obj = i + 1;

		struct scion_border_router *br = calloc(1, sizeof(*br));
		if (!br) {
			return SCION_ERR_TOPOLOGY_INVALID;
		}
		// extract and parse internal border router address
		char internal[64];
		tok_str(json, tok, object_find(json, tok, obj, "internal_addr"), internal, sizeof(internal));

		size_t addrStrLen = strnlen(internal, 64);
		int ret = parse_address(internal, addrStrLen, &br->addr, &br->addr_len);
		if (ret != 0) {
			return SCION_ERR_TOPOLOGY_INVALID;
		}

		if (parse_interfaces(json, tok, object_find(json, tok, obj, "interfaces"), br) < 0) {
			return SCION_ERR_TOPOLOGY_INVALID;
		}

		scion_list_append(topo->border_routers, br);
		i = tok_skip(tok, obj);
	}
	return EXIT_SUCCESS;
}

int parse_topology(const char *json, size_t bufSize, struct scion_topology *topo)
{
	int ret = EXIT_SUCCESS;
	jsmn_parser parser;
	jsmntok_t tok[MAXTOK];

	jsmn_init(&parser);

	int r = jsmn_parse(&parser, json, strnlen(json, bufSize), tok, MAXTOK);

	if (r < 0) {
		ret = SCION_ERR_TOPOLOGY_INVALID;
		return ret;
	}
	// Try extracting Core attribute
	int attributes = object_find(json, tok, 0, "attributes");
	int is_core = array_contains(json, tok, attributes, "core");
	topo->local_core = is_core;

	// Extract and parse ISD-AS
	char isd_as[16];
	tok_str(json, tok, object_find(json, tok, 0, "isd_as"), isd_as, sizeof(isd_as));
	size_t isd_as_str_len = strnlen(isd_as, 16);
	ret = scion_ia_parse(isd_as, isd_as_str_len, &topo->ia);
	if (ret != 0) {
		return SCION_ERR_TOPOLOGY_INVALID;
	}

	// Extract and parse control service
	ret = parse_control_service(json, tok, object_find(json, tok, 0, "control_service"), topo);
	if (ret < 0) {
		return ret;
	}
	// Take the address familiy of the control service as address familiy of the topology
	topo->local_addr_family = topo->cs_addr.ss_family;
	// Extract and parse border routers
	ret = parse_border_routers(json, tok, object_find(json, tok, 0, "border_routers"), topo);
	return ret;
}

static int scion_topology_from_stream(struct scion_topology **topology, FILE *f)
{
	int ret;

	struct scion_topology *topology_storage = malloc(sizeof(*topology_storage));
	if (topology_storage == NULL) {
		return SCION_ERR_MEM_ALLOC_FAIL;
	}

	// Initialize empty topology
	topology_storage->ia = 0;
	topology_storage->local_core = false;
	topology_storage->cs_addr_len = 0;
	topology_storage->border_routers = scion_list_create(SCION_LIST_CUSTOM_FREE(scion_free_border_router));

	// load json
	ret = fseek(f, 0L, SEEK_END);
	if (ret != 0) {
		ret = SCION_ERR_TOPOLOGY_INVALID;
		goto cleanup_topology;
	}
	long pos = ftell(f);
	if (pos < 0) {
		ret = SCION_ERR_TOPOLOGY_INVALID;
		goto cleanup_topology;
	}
	size_t size = (size_t)pos;
	char *raw_json = malloc(size + 1);
	if (raw_json == NULL) {
		ret = SCION_ERR_MEM_ALLOC_FAIL;
		goto cleanup_topology;
	}
	ret = fseek(f, 0L, SEEK_SET);
	if (ret != 0) {
		ret = SCION_ERR_TOPOLOGY_INVALID;
		goto cleanup_topology;
	}
	if (fread(raw_json, 1, size + 1, f) != size) {
		ret = SCION_ERR_TOPOLOGY_INVALID;
		goto cleanup_topology;
	}
	raw_json[size] = 0x00;
	ret = parse_topology(raw_json, size, topology_storage);

	free(raw_json);

cleanup_topology:
	if (ret < 0) {
		scion_topology_free(topology_storage);
	} else {
		*topology = topology_storage;
	}

	return ret;
}

int scion_topology_from_file(struct scion_topology **topology, const char *path)
{
	assert(topology);

	// populate topology using topology.json
	FILE *f = fopen(path, "r");
	if (f == NULL) {
		return SCION_ERR_FILE_NOT_FOUND;
	}

	int ret = scion_topology_from_stream(topology, f);
	if (ret < 0) {
		(void)fclose(f);
	}

	return ret;
}

int scion_topology_next_underlay_hop(struct scion_topology *topology, scion_ifid ifid, struct scion_underlay *underlay)
{
	assert(topology);
	assert(topology->border_routers);
	assert(underlay);

	struct scion_list_node *curr = topology->border_routers->first;
	while (curr) {
		struct scion_border_router *br = curr->value;
		if (br != NULL) {
			if (ifid == SCION_INTERFACE_ANY) {
				underlay->addr = br->addr;
				underlay->addrlen = br->addr_len;
				underlay->addr_family = br->addr.ss_family;
				return 0;
			}
			for (size_t i = 0; i < br->ifid_len; i++) {
				scion_ifid currInterface = br->ifids[i];
				if (currInterface == ifid) {
					underlay->addr = br->addr;
					underlay->addrlen = br->addr_len;
					underlay->addr_family = br->addr.ss_family;
					return 0;
				}
			}
		}
		curr = curr->next;
	}

	return SCION_ERR_TOPOLOGY_INVALID;
}

bool scion_topology_is_local_as_core(struct scion_topology *t)
{
	if (t == NULL) {
		return false;
	}
	return t->local_core;
}

scion_ia scion_topology_get_local_ia(struct scion_topology *topo)
{
	assert(topo != NULL);

	return topo->ia;
}
