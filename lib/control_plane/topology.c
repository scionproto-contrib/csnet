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

void scion_free_border_router(struct scion_border_router *br)
{
	if (br == NULL) {
		return;
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

// Taken from:
// https://github.com/zserge/jsmn/blob/25647e692c7906b96ffd2b05ca54c097948e879c/example/simple.c#L15
// minimally adapted.
static bool jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
	assert(tok->end - tok->start > 0);
	uint len = (uint)(tok->end - tok->start);

	if (tok->type == JSMN_STRING && strlen(s) == len && strncmp(json + tok->start, s, len) == 0) {
		return true;
	}
	return false;
}

static int parse_address(char *buff, size_t buff_len, struct sockaddr_storage *addr, socklen_t *addr_len)
{
	// Find last colon
	char *colon_ptr = scion_memrchr(buff, ':', buff_len);
	if (colon_ptr == NULL) {
		return SCION_TOPOLOGY_INVALID;
	}

	// IP
	size_t ip_len = (size_t)(colon_ptr - buff);
	if (buff_len == 0) {
		return SCION_TOPOLOGY_INVALID;
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
			return SCION_TOPOLOGY_INVALID;
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
			return SCION_TOPOLOGY_INVALID;
		}

		port_storage = &addr_in->sin_port;
	}

	// Port
	size_t port_len = (size_t)((ssize_t)buff_len - (colon_ptr + 1 - buff));
	if (port_len < 1) {
		return SCION_TOPOLOGY_INVALID;
	}
	char port[port_len + 1];
	(void)memcpy(port, colon_ptr + 1, port_len);
	port[port_len] = 0x00;
	*port_storage = htons((uint16_t)strtoul(port, NULL, 10));

	return 0;
}

int scion_topology_from_file(struct scion_topology **topology, const char *path)
{
	assert(topology);
	int ret;

	struct scion_topology *topology_storage = malloc(sizeof(*topology_storage));
	if (topology_storage == NULL) {
		return SCION_MEM_ALLOC_FAIL;
	}

	// Initialize empty topology
	topology_storage->ia = 0;
	topology_storage->local_core = false;
	topology_storage->cs_addr_len = 0;
	topology_storage->border_routers = scion_list_create(SCION_LIST_CUSTOM_FREE(scion_free_border_router));

	// populate topology using topology.json
	FILE *f = fopen(path, "r");
	if (f == NULL) {
		ret = SCION_FILE_NOT_FOUND;
		goto cleanup_topology;
	}

	// load json
	ret = fseek(f, 0L, SEEK_END);
	if (ret != 0) {
		ret = SCION_TOPOLOGY_INVALID;
		goto cleanup_topo_file;
	}
	long pos = ftell(f);
	if (pos < 0) {
		ret = SCION_TOPOLOGY_INVALID;
		goto cleanup_topo_file;
	}
	size_t size = (size_t)pos;
	char *raw_json = malloc(size + 1);
	if (raw_json == NULL) {
		ret = SCION_MEM_ALLOC_FAIL;
		goto cleanup_topo_file;
	}
	ret = fseek(f, 0L, SEEK_SET);
	if (ret != 0) {
		ret = SCION_TOPOLOGY_INVALID;
		goto cleanup_topo_file;
	}
	if (fread(raw_json, 1, size + 1, f) != size) {
		ret = SCION_TOPOLOGY_INVALID;
		goto cleanup_topo_file;
	}
	raw_json[size] = 0x00;

	jsmn_parser parser;
	jsmntok_t tokens[256];
	jsmn_init(&parser);

	ret = jsmn_parse(
		&parser, (const char *)raw_json, strlen((const char *)raw_json), tokens, sizeof(tokens) / sizeof(tokens[0]));
	if (ret < 0) {
		ret = SCION_TOPOLOGY_INVALID;
		goto cleanup_json;
	}
	if (ret < 1 || tokens[0].type != JSMN_OBJECT) {
		ret = SCION_TOPOLOGY_INVALID;
		goto cleanup_json;
	}

	bool found = false;
	int actual_tokens = ret;
	ret = 0;
	int i = 1;
	jsmntok_t t;

	while (i < actual_tokens) {
		// Local AS is a CORE AS
		if (jsoneq((const char *)raw_json, &tokens[i], "core")) {
			// Local AS is a CORE AS
			topology_storage->local_core = true;
			i++;

		} else if (jsoneq((const char *)raw_json, &tokens[i], "isd_as")) {
			// Local ISD-AS number
			i++;
			if (tokens[i].type == JSMN_STRING) {
				t = tokens[i];
				uint16_t len = (uint16_t)(t.end - t.start);
				ret = scion_ia_parse(raw_json + t.start, len, &topology_storage->ia);
				if (ret != 0) {
					ret = SCION_TOPOLOGY_INVALID;
					goto cleanup_json;
				}
			}

		} else if (jsoneq((const char *)raw_json, &tokens[i], "control_service")) {
			// Get Control Server IP and PORT. If multiple, take first.
			found = false;

			// Forward to address
			while (i < actual_tokens && !found) {
				if (jsoneq((const char *)raw_json, &tokens[i], "addr")) {
					found = true;
				}
				i++;
			}

			// Handle Control Server IP and PORT
			if (tokens[i].type == JSMN_STRING) {
				t = tokens[i];
				size_t len = (size_t)(t.end - t.start);

				ret = parse_address(
					raw_json + t.start, len, &topology_storage->cs_addr, &topology_storage->cs_addr_len);
				if (ret != 0) {
					goto cleanup_json;
				}
			}

		} else if (jsoneq((const char *)raw_json, &tokens[i], "border_routers")) {
			// Get IP and PORT of all Border Routers
			i++;
			if (i < actual_tokens) { // Check that we haven't reached the end.
				t = tokens[i];
				uint32_t end_ptr = (uint32_t)t.end;
				i++;
				bool end_reached = false;
				// Border Routers

				while (i < actual_tokens && !end_reached) {
					// Skip to next BR internal_addr or check end of BR list
					found = false;
					while (i < actual_tokens && !found && !end_reached) {
						t = tokens[i];
						if (jsoneq((const char *)raw_json, &tokens[i], "internal_addr")) {
							found = true;
						}
						if ((uint32_t)t.start >= end_ptr) {
							end_reached = true;
						} else {
							i++;
						}
					}

					if (i < actual_tokens && !end_reached) {
						if (tokens[i].type != JSMN_STRING) {
							// Found wrong field
							ret = SCION_TOPOLOGY_INVALID;
							goto cleanup_json;
						}
						if (i + 3 >= actual_tokens) {
							// no IFID field
							ret = SCION_TOPOLOGY_INVALID;
							goto cleanup_json;
						}

						struct scion_border_router *br = malloc(sizeof(*br));
						br->addr_len = 0;

						// BR IP and PORT
						t = tokens[i];
						size_t len = (size_t)(t.end - t.start);

						ret = parse_address(raw_json + t.start, len, &br->addr, &br->addr_len);
						if (ret != 0) {
							scion_free_border_router(br);
							goto cleanup_json;
						}

						// Use border router address family as topology address family (we assume that the whole
						// topology has the same address family anyway)
						topology_storage->local_addr_family = br->addr.ss_family;

						// BR IFID
						// jump to IFID
						while (!jsoneq((const char *)raw_json, &tokens[i], "interfaces")) {
							i++;
						}
						i += 2;

						if (tokens[i].type != JSMN_STRING) {
							// Found wrong field
							scion_free_border_router(br);
							ret = SCION_TOPOLOGY_INVALID;
							goto cleanup_json;
						}
						t = tokens[i];
						len = (uint)(t.end - t.start);
						char ifid[len + 1];
						(void)memcpy(ifid, raw_json + t.start, len);
						ifid[len] = 0x00;
						br->ifid = strtoul(ifid, NULL, 10);

						scion_list_append(topology_storage->border_routers, br);

						i++;
					}
				}
			}

		} else {
			i++;
		}
	}

cleanup_json:
	free(raw_json);

cleanup_topo_file:
	fclose(f);

cleanup_topology:
	if (ret < 0) {
		scion_topology_free(topology_storage);
	} else {
		*topology = topology_storage;
	}

	return ret;
}

int scion_topology_next_underlay_hop(
	struct scion_topology *topology, scion_interface_id ifid, struct scion_underlay *underlay)
{
	assert(topology);
	assert(topology->border_routers);
	assert(underlay);

	struct scion_list_node *curr = topology->border_routers->first;
	while (curr) {
		struct scion_border_router *br = curr->value;
		if (br != NULL) {
			if (ifid == SCION_INTERFACE_ANY || br->ifid == ifid) {
				underlay->addr = br->addr;
				underlay->addrlen = br->addr_len;
				underlay->addr_family = br->addr.ss_family;
				return 0;
			}
		}
		curr = curr->next;
	}

	return SCION_TOPOLOGY_INVALID;
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
