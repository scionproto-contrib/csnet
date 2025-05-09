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

	for (size_t i = 0; i < n; i++) {
		int *v = &((int *)s)[n - 1 - i];
		if (*v == c) {
			return v;
		}
	}

	return NULL;
};
#else
#define scion_memrchr memrchr
#endif

void scion_free_border_router(struct scion_border_router *br)
{
	if (br == NULL) {
		return;
	}
	br->ifid = 0;
	if (br->ip != NULL) {
		free(br->ip);
		br->ip = NULL;
	}
	br->port = 0;
	free(br);
}

void scion_topology_free(struct scion_topology *topo)
{
	if (topo == NULL) {
		return;
	}
	if (topo->cs_ip != NULL) {
		free(topo->cs_ip);
		topo->cs_ip = NULL;
	}
	if (topo->border_routers != NULL) {
		scion_list_free(topo->border_routers, (scion_list_value_free)scion_free_border_router);
		topo->border_routers = NULL;
	}
	topo->cs_port = 0;
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
	topology_storage->cs_ip = NULL;
	topology_storage->cs_port = 0;
	topology_storage->border_routers = scion_list_create();

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
				uint len = (uint)(t.end - t.start);
				// Find Colon
				char *colon_ptr = scion_memrchr(raw_json + t.start, 0x3a, len); // 0x3a == ':'
				if (colon_ptr == NULL) {
					ret = SCION_TOPOLOGY_INVALID;
					goto cleanup_json;
				}

				// IP
				len = (uint)((int)(colon_ptr - raw_json) - t.start);
				if (len < 1) {
					ret = SCION_TOPOLOGY_INVALID;
					goto cleanup_json;
				}
				if (memchr(raw_json + t.start, 0x5b, len) != NULL && memchr(raw_json + t.start, 0x5d, len) != NULL) {
					// 0x5b == '[' and 0x5d == ']'
					// IPv6, which was "[IP]:Port", do not copy "[" and "]"
					len = len - 2;
					topology_storage->cs_ip = malloc(len + 1);
					(void)memcpy(topology_storage->cs_ip, raw_json + t.start + 1, len);
					topology_storage->cs_ip[len] = 0x00;

					// Validate IP
					struct in6_addr ipv6_addr;
					if (inet_pton(AF_INET6, topology_storage->cs_ip, &ipv6_addr) != 1) {
						ret = SCION_TOPOLOGY_INVALID;
						goto cleanup_json;
					}
				} else {
					topology_storage->cs_ip = malloc(len + 1);
					(void)memcpy(topology_storage->cs_ip, raw_json + t.start, len);
					topology_storage->cs_ip[len] = 0x00;

					// Validate IP
					struct in_addr ipv4_addr;
					if (inet_pton(AF_INET, topology_storage->cs_ip, &ipv4_addr) != 1) {
						ret = SCION_TOPOLOGY_INVALID;
						goto cleanup_json;
					}
				}

				// Port
				len = (uint)(t.end - (int)(colon_ptr + 1 - raw_json));
				if (len < 1) {
					ret = SCION_TOPOLOGY_INVALID;
					goto cleanup_json;
				}
				char port[len + 1];
				(void)memcpy(port, colon_ptr + 1, len);
				port[len] = 0x00;
				topology_storage->cs_port = (uint16_t)strtoul(port, NULL, 10);
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
						br->ip = NULL;

						// BR IP and PORT
						t = tokens[i];
						uint len = (uint)(t.end - t.start);
						// Find Colon
						char *colon_ptr = scion_memrchr(raw_json + t.start, 0x3a, len);
						if (colon_ptr == NULL) {
							scion_free_border_router(br);
							ret = SCION_TOPOLOGY_INVALID;
							goto cleanup_json;
						}

						// IP
						len = (uint)((int)(colon_ptr - raw_json) - t.start);
						if (len < 1) {
							scion_free_border_router(br);
							ret = SCION_TOPOLOGY_INVALID;
							goto cleanup_json;
						}
						if (memchr(raw_json + t.start, 0x5b, len) != NULL
							&& memchr(raw_json + t.start, 0x5d, len) != NULL) {
							// 0x5b == '[' and 0x5d == ']'
							// IPv6, which was "[IP]:Port", do not copy "[" and "]"
							len = len - 2;
							br->ip = malloc(len + 1);
							(void)memcpy(br->ip, raw_json + t.start + 1, len);
							br->ip[len] = 0x00;

							// Validate IP
							struct in6_addr ipv6_addr;
							if (inet_pton(AF_INET6, br->ip, &ipv6_addr) != 1) {
								scion_free_border_router(br);
								ret = SCION_TOPOLOGY_INVALID;
								goto cleanup_json;
							}
							// Set local address family
							topology_storage->local_addr_family = AF_INET6;
						} else {
							br->ip = malloc(len + 1);
							(void)memcpy(br->ip, raw_json + t.start, len);
							br->ip[len] = 0x00;

							// Validate IP
							struct in_addr ipv4_addr;
							if (inet_pton(AF_INET, br->ip, &ipv4_addr) != 1) {
								scion_free_border_router(br);
								ret = SCION_TOPOLOGY_INVALID;
								goto cleanup_json;
							}
							// Set local address family
							topology_storage->local_addr_family = AF_INET;
						}

						// Port
						len = (uint)(t.end - (int)(colon_ptr + 1 - raw_json));
						if (len < 1) {
							scion_free_border_router(br);
							ret = SCION_TOPOLOGY_INVALID;
							goto cleanup_json;
						}
						char port[len + 1];
						(void)memcpy(port, colon_ptr + 1, len);
						port[len] = 0x00;
						br->port = (uint16_t)strtoul(port, NULL, 10);

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
						br->ifid = (uint16_t)strtoul(ifid, NULL, 10);

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

int scion_topology_next_underlay_hop(struct scion_topology *t, scion_interface ifid, struct scion_underlay *underlay)
{
	assert(t);
	assert(t->border_routers);
	assert(underlay);

	struct scion_linked_list_node *curr = t->border_routers->first;
	while (curr) {
		struct scion_border_router *br = curr->value;
		if (br != NULL) {
			if (ifid == SCION_INTERFACE_ANY || br->ifid == ifid) {
				if (strchr(br->ip, 0x2e) != NULL) { // 0x2e == '.'
					// ip contains "." -> IPv4
					struct sockaddr_in *next_addr = (struct sockaddr_in *)&underlay->addr;
					next_addr->sin_addr.s_addr = inet_addr(br->ip);
					next_addr->sin_family = AF_INET;
					next_addr->sin_port = htons(br->port);
					underlay->addrlen = sizeof(struct sockaddr_in);
					underlay->addr_family = SCION_AF_IPV4;
					return 0;
				} else {
					struct sockaddr_in6 *next_addr = (struct sockaddr_in6 *)&underlay->addr;
					int ret = inet_pton(AF_INET6, br->ip, &next_addr->sin6_addr);
					if (ret != 0) {
						return SCION_TOPOLOGY_INVALID;
					}
					next_addr->sin6_family = AF_INET6;
					next_addr->sin6_port = htons(br->port);
					underlay->addrlen = sizeof(struct sockaddr_in6);
					underlay->addr_family = SCION_AF_IPV6;
					return 0;
				}
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
