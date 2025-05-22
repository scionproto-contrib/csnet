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

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/info_field.h"
#include "common/isd_as.h"
#include "common/path_segment.h"
#include "control_plane/fetch.h"
#include "control_plane/graph.h"
#include "control_plane/path_metadata.h"
#include "data_plane/path.h"
#include "util/endian.h"
#include "util/list.h"

// Internally used structs

struct input_segment {
	struct scion_path_segment *segment;
	enum scion_segment_type type;
};

struct vertex {
	scion_ia ia;
	// For peering:
	scion_ia up_ia;
	uint16_t up_ifid;
	scion_ia down_ia;
	uint16_t down_ifid;
};

struct tuple {
	struct vertex src;
	struct vertex dst;
	uint16_t peer;
};

struct edge {
	size_t weight;
	size_t shortcut;
	uint16_t peer;
};

struct solution_edge {
	struct edge *edge;
	struct vertex *src;
	struct vertex *dst;
	struct input_segment *segment;
};

struct path_solution {
	struct scion_list *edges;
	struct vertex *current_vertex;
	struct input_segment *current_seg;
	size_t cost;
};

struct edge_map_node {
	struct input_segment *key;
	struct edge *value;
	struct edge_map_node *next;
};

struct vertex_info_node {
	struct vertex *key;
	struct edge_map_node *value;
	struct vertex_info_node *next;
};

struct dmg_node {
	struct vertex *key;
	struct vertex_info_node *value;
	struct dmg_node *next;
};

struct dmg {
	struct dmg_node *start_node;
	struct input_segment **ups;
	uint16_t ups_length;
	struct input_segment **cores;
	uint16_t cores_length;
	struct input_segment **downs;
	uint16_t downs_length;
};

struct segment {
	struct scion_info_field *info_field;
	struct scion_list *hop_fields;
	// COMMENT: GO implementation includes a list of ASEntries but I can't seem to find a place where they are needed /
	// used. So I omit them here.
};

/*
 * ##################################################################
 * ########################### segment ##############################
 * ##################################################################
 */

static void free_segment(struct segment *seg)
{
	if (seg == NULL) {
		return;
	}
	if (seg->info_field != NULL) {
		free(seg->info_field);
		seg->info_field = NULL;
	}
	scion_list_free(seg->hop_fields);
	seg->hop_fields = NULL;
	free(seg);
}

/*
 * ##################################################################
 * ######################### vertex functions #######################
 * ##################################################################
 */

static int vertex_from_ia(scion_ia ia, struct vertex *v)
{
	assert(v);

	v->ia = ia;
	v->up_ia = 0;
	v->up_ifid = 0;
	v->down_ia = 0;
	v->down_ifid = 0;
	return 0;
}

static int vertex_from_peer(scion_ia up_ia, uint16_t up_ifid, scion_ia down_ia, uint16_t down_ifid, struct vertex *v)
{
	assert(v);

	v->ia = 0;
	v->up_ia = up_ia;
	v->up_ifid = up_ifid;
	v->down_ia = down_ia;
	v->down_ifid = down_ifid;
	return 0;
}

static int reverse_vertex(struct vertex *v)
{
	assert(v);

	scion_ia old_up_ia = v->up_ia;
	uint16_t old_up_ifid = v->up_ifid;
	v->up_ia = v->down_ia;
	v->up_ifid = v->down_ifid;
	v->down_ia = old_up_ia;
	v->down_ifid = old_up_ifid;
	return 0;
}

static int copy_vertex(struct vertex *src, struct vertex *dst)
{
	assert(src);
	assert(dst);

	dst->ia = src->ia;
	dst->up_ia = src->up_ia;
	dst->up_ifid = src->up_ifid;
	dst->down_ia = src->down_ia;
	dst->down_ifid = src->down_ifid;
	return 0;
}

static bool compare_vertices(struct vertex *v1, struct vertex *v2)
{
	if (!v1 && !v2) {
		return true;
	} else if ((v1 && !v2) || (!v1 && v2)) {
		return false;
	} else if (v1->ia != v2->ia || v1->up_ia != v2->up_ia || v1->up_ifid != v2->up_ifid || v1->down_ia != v2->down_ia
			   || v1->down_ifid != v2->down_ifid) {
		return false;
	}
	return true;
}

/*
 * ##################################################################
 * ########################## edge functions ########################
 * ##################################################################
 */

static int edge_from_weight(size_t w, struct edge *e)
{
	assert(e);

	e->weight = w;
	e->shortcut = 0;
	e->peer = 0;
	return 0;
}

static int init_edge(struct edge *e, size_t weight, size_t shortcut, uint16_t peer)
{
	assert(e);

	e->weight = weight;
	e->shortcut = shortcut;
	e->peer = peer;
	return 0;
}

/*
 * ##################################################################
 * ######### solution_edge and solution_edge List functions #########
 * ##################################################################
 */

static int init_solution_edge(
	struct solution_edge *sol_edge, struct edge *e, struct vertex *src, struct vertex *dst, struct input_segment *seg)
{
	assert(sol_edge);

	sol_edge->edge = e;
	sol_edge->src = src;
	sol_edge->dst = dst;
	sol_edge->segment = seg;
	return 0;
}

static int copy_solution_edge_list(struct scion_list *new_list, struct scion_list *old_list)
{
	assert(new_list);
	assert(old_list);

	int ret;

	struct scion_list_node *curr = old_list->first;
	while (curr) {
		struct solution_edge *old_edge = curr->value;
		struct solution_edge *new_edge = malloc(sizeof(*new_edge));
		ret = init_solution_edge(new_edge, old_edge->edge, old_edge->src, old_edge->dst, old_edge->segment);
		if (ret != 0) {
			return ret;
		}
		scion_list_append(new_list, (void *)new_edge);
		curr = curr->next;
	}
	return 0;
}

/*
 * ############# free solution_edge and solution_edge List #############
 */

static void free_solution_edge(struct solution_edge *sol_edge)
{
	if (sol_edge == NULL) {
		return;
	}
	sol_edge->edge = NULL;
	sol_edge->src = NULL;
	sol_edge->dst = NULL;
	sol_edge->segment = NULL;
	free(sol_edge);
}

/*
 * ##################################################################
 * ################### path_solution functions ######################
 * ##################################################################
 */

static int init_path_solution(
	struct path_solution *path_sol, struct scion_list *edges, struct vertex *v, struct input_segment *seg, size_t c)
{
	assert(path_sol);

	path_sol->edges = edges;
	path_sol->current_vertex = v;
	path_sol->current_seg = seg;
	path_sol->cost = c;
	return 0;
}

/*
 * ############# free path_solution and PathSolutionList #############
 */

static void free_path_solution(struct path_solution *path_sol)
{
	assert(path_sol);

	scion_list_free(path_sol->edges);
	path_sol->edges = NULL;
	free(path_sol);
}

/*
 * ##################################################################
 * ####################### Directed Multigraph ######################
 * ##################################################################
 */

/*
 * ###################### dmg_node subfunctions ######################
 */

static struct dmg_node *get_dmg_node(struct dmg_node *start_node, struct vertex *key)
{
	// TODO: better error handling in case of null key? probably shouldn't happen.
	if (!key) {
		return NULL;
	}

	struct dmg_node *current_node = start_node;

	while (current_node) {
		if (compare_vertices(key, current_node->key)) {
			return current_node;
		}
		current_node = current_node->next;
	}
	return NULL;
}

static struct dmg_node *get_last_dmg_node(struct dmg_node *start_node)
{
	struct dmg_node *current_node = start_node;
	while (current_node->next) {
		current_node = current_node->next;
	}
	return current_node;
}

static int init_dmg_node(struct dmg_node *node, struct vertex *v)
{
	assert(node);

	int ret;

	struct vertex *key = malloc(sizeof(*key));
	ret = copy_vertex(v, key);
	if (ret != 0) {
		free(key);
		return ret;
	}
	node->key = key;
	node->value = NULL;
	node->next = NULL;

	return 0;
}

static struct vertex *get_vertex_from_graph(struct dmg *dmg, scion_ia ia)
{
	int ret;
	struct vertex v;
	ret = vertex_from_ia(ia, &v);
	if (ret != 0) {
		return NULL;
	}

	struct dmg_node *dmg_node = get_dmg_node(dmg->start_node, &v);

	if (dmg_node) {
		return dmg_node->key;
	}
	return NULL;
}

/*
 * ################# vertex_info_node subfunctions ###################
 */

static struct vertex_info_node *get_vertex_info_node(struct vertex_info_node *start_node, struct vertex *key)
{
	// TODO: better error handling in case of null key? probably shouldn't happen.
	if (!key) {
		return NULL;
	}

	struct vertex_info_node *current_node = start_node;

	while (current_node) {
		if (compare_vertices(key, current_node->key)) {
			return current_node;
		}
		current_node = current_node->next;
	}
	return NULL;
}

static struct vertex_info_node *get_last_vertex_info_node(struct vertex_info_node *start_node)
{
	struct vertex_info_node *current_node = start_node;
	while (current_node->next) {
		current_node = current_node->next;
	}
	return current_node;
}

static int init_vertex_info_node(struct vertex_info_node *node, struct vertex *v)
{
	assert(node);

	int ret;

	struct vertex *key = malloc(sizeof(*key));
	ret = copy_vertex(v, key);
	if (ret != 0) {
		// ret != 0 implies key == NULL, meaning malloc failed
		return SCION_MEM_ALLOC_FAIL;
	}
	node->key = key;
	node->value = NULL;
	node->next = NULL;
	return 0;
}

/*
 * ################## edge_map_node subfunctions ####################
 */

static struct edge_map_node *get_edge_map_node(struct edge_map_node *start_node, struct input_segment *key)
{
	// TODO: better error handling in case of null key? probably shouldn't happen.
	if (!key) {
		return NULL;
	}

	struct edge_map_node *current_node = start_node;

	while (current_node) {
		if (key == current_node->key) {
			return current_node;
		}
		current_node = current_node->next;
	}
	return NULL;
}

static struct edge_map_node *get_last_edge_map_node(struct edge_map_node *start_node)
{
	struct edge_map_node *current_node = start_node;
	while (current_node->next) {
		current_node = current_node->next;
	}
	return current_node;
}

static int init_edge_map_node(struct edge_map_node *node, struct input_segment *key)
{
	assert(node);
	assert(key);

	node->key = key;
	node->value = NULL;
	node->next = NULL;
	return 0;
}

/*
 * ################# Freeing the dmg subfunctions ##################
 */

static void free_edge_map(struct edge_map_node *start_node)
{
	if (start_node == NULL) {
		return;
	}

	struct edge_map_node *current_node = start_node;
	struct edge_map_node *previous_node;

	while (current_node) {
		previous_node = current_node;
		current_node = current_node->next;
		if (previous_node->value != NULL) {
			free(previous_node->value);
		}
		free(previous_node);
	}
}

static void free_vertex_info(struct vertex_info_node *start_node)
{
	if (start_node == NULL) {
		return;
	}

	struct vertex_info_node *current_node = start_node;
	struct vertex_info_node *previous_node;

	while (current_node) {
		previous_node = current_node;
		current_node = current_node->next;
		if (previous_node->key != NULL) {
			free(previous_node->key);
		}
		free_edge_map(previous_node->value);
		free(previous_node);
	}
}

static void free_dmg_node(struct dmg_node *start_node)
{
	if (start_node == NULL) {
		return;
	}

	struct dmg_node *current_node = start_node;
	struct dmg_node *previous_node;

	while (current_node) {
		previous_node = current_node;
		current_node = current_node->next;
		if (previous_node->key != NULL) {
			free(previous_node->key);
		}
		free_vertex_info(previous_node->value);
		free(previous_node);
	}
}

// TODO: rethink input_segment freeing. Potentially we can save memory here.

// We free the graph starting from the start_node. The InputSegments are freed here and not in
// free_edge_map.

// We free the InputSegments but not the ScionPathSegments inside of the InputSegments.
// They are provided by the caller and give the responsibility to the caller to free them.
static void free_dmg_internal(struct dmg *graph)
{
	uint16_t i;
	if (graph == NULL) {
		return;
	}
	if (graph->start_node) {
		free_dmg_node(graph->start_node);
		graph->start_node = NULL;
	}
	if (graph->ups != NULL) {
		for (i = 0; i < graph->ups_length; i++) {
			free(graph->ups[i]);
			graph->ups[i] = NULL;
		}
		free(graph->ups);
		graph->ups = NULL;
		graph->ups_length = 0;
	}
	if (graph->cores != NULL) {
		for (i = 0; i < graph->cores_length; i++) {
			free(graph->cores[i]);
			graph->cores[i] = NULL;
		}
		free(graph->cores);
		graph->cores = NULL;
		graph->cores_length = 0;
	}
	if (graph->downs != NULL) {
		for (i = 0; i < graph->downs_length; i++) {
			free(graph->downs[i]);
			graph->downs[i] = NULL;
		}
		free(graph->downs);
		graph->downs = NULL;
		graph->downs_length = 0;
	}
}

/*
 * ################# Adding an edge to the dmg ##################
 */

static int add_edge(
	struct dmg *graph, struct vertex *src, struct vertex *dst, struct input_segment *seg, struct edge *e)
{
	assert(graph);
	assert(src);
	assert(dst);
	assert(seg);
	assert(e);

	int ret;

	struct dmg_node *start_node = graph->start_node;
	if (!start_node) {
		// graph was empy so far
		struct dmg_node *src_node = malloc(sizeof(*src_node));
		ret = init_dmg_node(src_node, src);
		if (ret != 0) {
			free(src_node);
			return ret;
		}

		struct vertex_info_node *src_vertex_info_node = malloc(sizeof(*src_vertex_info_node));
		ret = init_vertex_info_node(src_vertex_info_node, dst);
		if (ret != 0) {
			free(src_node);
			free(src_vertex_info_node);
			return ret;
		}
		src_node->value = src_vertex_info_node;

		struct edge_map_node *dst_edge_map_node = malloc(sizeof(*dst_edge_map_node));
		ret = init_edge_map_node(dst_edge_map_node, seg);
		if (ret != 0) {
			free(src_node);
			free(src_vertex_info_node);
			free(dst_edge_map_node);
			return ret;
		}

		dst_edge_map_node->value = e;
		src_vertex_info_node->value = dst_edge_map_node;
		graph->start_node = src_node;
		return 0;
	}

	struct dmg_node *src_dmg_node = get_dmg_node(start_node, src);
	if (!src_dmg_node) {
		src_dmg_node = malloc(sizeof(*src_dmg_node));
		ret = init_dmg_node(src_dmg_node, src);
		if (ret != 0) {
			free(src_dmg_node);
			return ret;
		}
		struct dmg_node *last_dmg_node = get_last_dmg_node(start_node);
		last_dmg_node->next = src_dmg_node;
	}

	struct vertex_info_node *dst_vertex_info_node = get_vertex_info_node(src_dmg_node->value, dst);
	if (!dst_vertex_info_node) {
		dst_vertex_info_node = malloc(sizeof(*dst_vertex_info_node));
		ret = init_vertex_info_node(dst_vertex_info_node, dst);
		if (ret != 0) {
			// We don't need to free src_dmg_node as it was successfully added to the graph.
			// free_dmg_internal will take care of it.
			free(dst_vertex_info_node);
			return ret;
		}

		if (src_dmg_node->value) {
			struct vertex_info_node *last_vertex_info_node = get_last_vertex_info_node(src_dmg_node->value);
			last_vertex_info_node->next = dst_vertex_info_node;
		} else {
			src_dmg_node->value = dst_vertex_info_node;
		}
	}

	// Technically this should never exist. Potentially could be simplified.
	struct edge_map_node *seg_edge_map_node = get_edge_map_node(dst_vertex_info_node->value, seg);
	if (!seg_edge_map_node) {
		seg_edge_map_node = malloc(sizeof(*seg_edge_map_node));
		ret = init_edge_map_node(seg_edge_map_node, seg);
		if (ret != 0) {
			// We don't need to free src_dmg_node or dst_vertex_info_node as they were successfully added to the graph.
			// free_dmg_internal will take care of them.
			free(seg_edge_map_node);
			return ret;
		}
		if (dst_vertex_info_node->value) {
			struct edge_map_node *last_edge_map_node = get_last_edge_map_node(dst_vertex_info_node->value);
			last_edge_map_node->next = seg_edge_map_node;
		} else {
			dst_vertex_info_node->value = seg_edge_map_node;
		}
	}

	seg_edge_map_node->value = e;
	return 0;
}

/*
 * ##################################################################
 * ####################### dmg Construction #########################
 * ##################################################################
 */

static int traverse_segment(struct dmg *graph, struct input_segment *seg)
{
	assert(graph);
	assert(seg);

	int ret;
	struct vertex src;
	struct vertex dst;
	struct edge *e;

	struct scion_path_segment *path_seg = seg->segment;
	struct scion_as_entry **as_entries = path_seg->as_entries;
	size_t as_entries_length = path_seg->as_entries_length;

	if (seg->type == CORE_SEGMENT) {
		ret = vertex_from_ia(as_entries[as_entries_length - 1]->local, &src);
		if (ret != 0) {
			return ret;
		}
		ret = vertex_from_ia(as_entries[0]->local, &dst);
		if (ret != 0) {
			return ret;
		}
		e = malloc(sizeof(*e));
		ret = edge_from_weight(as_entries_length - 1, e);
		if (ret != 0) {
			return ret;
		}
		ret = add_edge(graph, &src, &dst, seg, e);
		if (ret != 0) {
			free(e);
		}
		return ret;
	}

	scion_ia pinned_ia = as_entries[as_entries_length - 1]->local;
	struct scion_list *tuples;
	for (size_t i = as_entries_length; i > 0; i--) {
		struct scion_as_entry *curr_as_entry = as_entries[i - 1];
		scion_ia current_ia = curr_as_entry->local;
		tuples = scion_list_create(SCION_LIST_SIMPLE_FREE);

		if (i != as_entries_length) {
			struct tuple *t = malloc(sizeof(*t));
			if (t == NULL) {
				scion_list_free(tuples);
				return SCION_MEM_ALLOC_FAIL;
			}
			ret = vertex_from_ia(pinned_ia, &t->src);
			if (ret != 0) {
				scion_list_free(tuples);
				return ret;
			}
			ret = vertex_from_ia(current_ia, &t->dst);
			if (ret != 0) {
				scion_list_free(tuples);
				return ret;
			}
			t->peer = 0;
			scion_list_append(tuples, t);
		}

		// Peer Entries
		for (uint16_t j = 0; j < curr_as_entry->peer_entries_length; j++) {
			uint16_t ingress = curr_as_entry->peer_entries[j]->hopfield.cons_ingress;
			uint16_t remote = curr_as_entry->peer_entries[j]->peer_interface;
			struct tuple *t = malloc(sizeof(*t));
			if (t == NULL) {
				scion_list_free(tuples);
				return SCION_MEM_ALLOC_FAIL;
			}
			ret = vertex_from_ia(pinned_ia, &t->src);
			if (ret != 0) {
				scion_list_free(tuples);
				return ret;
			}
			ret = vertex_from_peer(current_ia, ingress, curr_as_entry->peer_entries[j]->peer, remote, &t->dst);
			if (ret != 0) {
				scion_list_free(tuples);
				return ret;
			}
			t->peer = j + 1;
			scion_list_append(tuples, t);
		}

		struct scion_list_node *curr = tuples->first;
		while (curr != NULL) {
			struct tuple *t = curr->value;
			size_t weight = as_entries_length - i;

			if (seg->type == DOWN_SEGMENT) {
				ret = reverse_vertex(&t->dst);
				if (ret != 0) {
					scion_list_free(tuples);
					return ret;
				}
				struct vertex old_src = t->src;
				t->src = t->dst;
				t->dst = old_src;
				if (t->peer != 0) {
					weight += 1;
				}
			}
			e = malloc(sizeof(*e));
			ret = init_edge(e, weight, i - 1, t->peer);
			if (ret != 0) {
				scion_list_free(tuples);
				return ret;
			}
			ret = add_edge(graph, &t->src, &t->dst, seg, e);
			if (ret != 0) {
				free(e);
				scion_list_free(tuples);
				return ret;
			}
			curr = curr->next;
		}
		scion_list_free(tuples);
	}
	return 0;
}

/*
 * ########################## new_dmg ############################
 */

/*
 * FUNCTION: new_dmg
 * -----------------
 * Creates a Directed Multigraph from the provided ScionPathSegments.
 *
 * Arguments:
 *      - struct scion_path_segment **ups: Pointer to an array of scion_path_segment pointers. All ScionPathSegments
 * have the type UP_SEGMENT.
 *      - uint16_t ups_length: Length of the ups array.
 *      - struct scion_path_segment **cores: Pointer to an array of scion_path_segment pointers. All ScionPathSegments
 * have the type CORE_SEGMENT.
 *      - uint16_t cores_length: Length of the cores array.
 *      - struct scion_path_segment **downs: Pointer to an array of scion_path_segment pointers. All ScionPathSegments
 * have the type DOWN_SEGMENT.
 *      - uint16_t downs_length: Length of the downs array.
 * 		- struct dmg *dmg: Pointer to a dmg struct into which the created Directed Multigraph will be stored.
 *
 * Returns:
 * 		- An integer status code, 0 for success or an error code as defined in error.h.
 */
static int new_dmg(struct scion_path_segment **ups, size_t ups_length, struct scion_path_segment **cores,
	size_t cores_length, struct scion_path_segment **downs, size_t downs_length, struct dmg *dmg)
{
	assert(dmg);
	assert(ups_length == 0 || ups);
	assert(cores_length == 0 || cores);
	assert(downs_length == 0 || downs);

	int ret;
	size_t i;
	struct input_segment *seg;

	// "zero" initalize dmg
	dmg->start_node = NULL;
	dmg->ups = NULL;
	dmg->ups_length = 0;
	dmg->cores = NULL;
	dmg->cores_length = 0;
	dmg->downs = NULL;
	dmg->downs_length = 0;

	// Malloc input_segment arrays
	if (ups_length > 0) {
		dmg->ups = malloc(ups_length * sizeof(*dmg->ups));
	}
	if (cores_length > 0) {
		dmg->cores = malloc(cores_length * sizeof(*dmg->cores));
	}
	if (downs_length > 0) {
		dmg->downs = malloc(downs_length * sizeof(*dmg->downs));
	}

	for (i = 0; i < ups_length; i++) {
		seg = malloc(sizeof(*seg));
		seg->segment = ups[i];
		seg->type = UP_SEGMENT;
		dmg->ups[i] = seg;
		dmg->ups_length += 1;
		ret = traverse_segment(dmg, seg);
		if (ret != 0) {
			return ret;
		}
	}

	for (i = 0; i < cores_length; i++) {
		seg = malloc(sizeof(*seg));
		seg->segment = cores[i];
		seg->type = CORE_SEGMENT;
		dmg->cores[i] = seg;
		dmg->cores_length += 1;
		ret = traverse_segment(dmg, seg);
		if (ret != 0) {
			return ret;
		}
	}

	for (i = 0; i < downs_length; i++) {
		seg = malloc(sizeof(*seg));
		seg->segment = downs[i];
		seg->type = DOWN_SEGMENT;
		dmg->downs[i] = seg;
		dmg->downs_length += 1;
		ret = traverse_segment(dmg, seg);
		if (ret != 0) {
			return ret;
		}
	}
	return 0;
}

/*
 * ##################################################################
 * ######################## Path Extraction #########################
 * ##################################################################
 */

static bool valid_next_seg(struct input_segment *curr_seg, struct input_segment *next_seg)
{
	if (curr_seg == NULL) {
		// If we have no current segment, any segment can be first.
		// https://github.com/scionproto/scion/blob/master/private/path/combinator/graph.go#L599 (Last visited May 14th
		// 2024)
		return true;
	}
	if (next_seg == NULL) {
		return false;
	}

	if (curr_seg->type == UP_SEGMENT) {
		return next_seg->type == CORE_SEGMENT || next_seg->type == DOWN_SEGMENT;
	} else if (curr_seg->type == CORE_SEGMENT) {
		return next_seg->type == DOWN_SEGMENT;
	} else {
		return false;
	}
}

/*
 * FUNCTION: scion_path_sol_less
 * -------------------
 * Determines if the path_solution a is 'less' than path_solution b. This is determined in order:
 * 		- number of hops
 * 		- number of segments
 * 		- segment IDs
 * 		- shortcut index
 *  	- peer entry index
 *
 * Arguments:
 *      - struct path_solution *a: Pointer to the first path_solution.
 * 		- struct path_solution *b: Pointer to the second path_solution.
 *
 * Returns:
 * 		- A Boolean, true if path_solution a is 'less', false if path_solution b is 'less' (or both are equal).
 */
static bool scion_path_sol_less(struct path_solution *a, struct path_solution *b)
{
	// if only one is null, we consider the other one to be 'less'
	// if both are null, we don't care
	if (a == NULL) {
		return false;
	}
	if (b == NULL) {
		return true;
	}

	// number of hops
	if (a->cost != b->cost) {
		return (a->cost < b->cost);
	}

	// number of segments
	if (a->edges->size != b->edges->size) {
		return (a->edges->size < b->edges->size);
	}

	struct scion_list_node *curr_a = a->edges->first;
	struct scion_list_node *curr_b = b->edges->first;
	struct solution_edge *sol_edge_a;
	struct solution_edge *sol_edge_b;
	// TODO: Potentially add Null checks?
	while ((curr_a != NULL) && (curr_b != NULL)) {
		sol_edge_a = curr_a->value;
		sol_edge_b = curr_b->value;

		// segment IDs
		uint16_t id_a = sol_edge_a->segment->segment->info.segment_id;
		uint16_t id_b = sol_edge_b->segment->segment->info.segment_id;
		if (id_a != id_b) {
			return (id_a < id_b);
		}

		// shortcut index
		size_t shortcut_a = sol_edge_a->edge->shortcut;
		size_t shortcut_b = sol_edge_b->edge->shortcut;
		if (shortcut_a != shortcut_b) {
			return (shortcut_a < shortcut_b);
		}

		// peer entry index
		uint16_t peer_a = sol_edge_a->edge->peer;
		uint16_t peer_b = sol_edge_b->edge->peer;
		if (peer_a != peer_b) {
			return (peer_a < peer_b);
		}

		curr_a = curr_a->next;
		curr_b = curr_b->next;
	}
	return false;
}

/*
 * FUNCTION: scion_sort_path_solutions
 * -------------------
 * Sorts a scion_linked_list of PathSolutions using scion_path_sol_less to compare two PathSolutions.
 *
 * Arguments:
 *      - struct scion_linked_list *paths: Pointer to the scion_linked_list.
 *
 * Returns:
 * 		- An integer status code, 0 for success or an error code as defined in error.h.
 */
static int scion_sort_path_solutions(struct scion_list *paths)
{
	assert(paths);

	if (paths->size <= 1) {
		return 0;
	}

	struct scion_list_node *curr_pos = paths->first;
	struct scion_list_node *curr_test;
	struct scion_list_node *candidate;

	while (curr_pos) {
		candidate = curr_pos;
		curr_test = curr_pos->next;
		while (curr_test) {
			struct path_solution *cand_path_sol = candidate->value;
			struct path_solution *test_path_sol = curr_test->value;
			if (scion_path_sol_less(test_path_sol, cand_path_sol)) {
				candidate = curr_test;
			}
			curr_test = curr_test->next;
		}
		if (curr_pos != candidate) {
			struct path_solution *old_cand_value = candidate->value;
			candidate->value = curr_pos->value;
			curr_pos->value = old_cand_value;
		}
		curr_pos = curr_pos->next;
	}

	return 0;
}

/*
 * FUNCTION: get_paths_from_graph
 * -------------------
 * Extracts all available paths from a source IA to a destination IA in a given dmg.
 *
 * Arguments:
 *      - struct dmg *dmg: Pointer to the dmg of the dmg from which we want to extract the paths.
 *      - IA src_ia: IA where the paths should start.
 *      - IA dst_ia: IA where the paths should end.
 * 		- struct scion_linked_list *paths: Pointer to a scion_linked_list into which the resulting path_solution
 * 		  structs will be stored.
 *
 * Returns:
 * 		- An integer status code, 0 for success or an error code as defined in error.h.
 */
static int get_paths_from_graph(struct dmg *dmg, scion_ia src_ia, scion_ia dst_ia, struct scion_list *paths)
{
	assert(dmg);
	assert(dmg->start_node);
	assert(paths);

	int ret;

	struct vertex *src = get_vertex_from_graph(dmg, src_ia);
	if (src == NULL) {
		return SCION_NO_PATHS;
	}

	struct vertex dst;
	ret = vertex_from_ia(dst_ia, &dst);
	if (ret != 0) {
		return ret;
	}

	struct scion_list *queue = scion_list_create(SCION_LIST_NO_FREE_VALUES);
	if (queue == NULL) {
		return SCION_MEM_ALLOC_FAIL;
	}

	struct scion_list *current_edge_list = scion_list_create(SCION_LIST_CUSTOM_FREE(free_solution_edge));
	if (current_edge_list == NULL) {
		ret = SCION_MEM_ALLOC_FAIL;
		goto exit;
	}

	struct path_solution *current_path_sol = malloc(sizeof(*current_path_sol));
	ret = init_path_solution(current_path_sol, current_edge_list, src, NULL, 0);
	if (ret != 0) {
		ret = SCION_MEM_ALLOC_FAIL;
		goto cleanup_edge_list;
	}
	scion_list_append(queue, (void *)current_path_sol);

	while (queue->size > 0) {
		current_path_sol = scion_list_pop(queue);
		struct dmg_node *current_dmg_node = get_dmg_node(dmg->start_node, current_path_sol->current_vertex);
		if (current_dmg_node) {
			struct vertex_info_node *curr_vertex_info_node = current_dmg_node->value;

			// iterate over every key - value pair
			while (curr_vertex_info_node) {
				struct vertex *next_vertex = curr_vertex_info_node->key;
				struct edge_map_node *curr_edge_map_node = curr_vertex_info_node->value;

				// iterate over every key - value pair
				while (curr_edge_map_node) {
					struct input_segment *seg = curr_edge_map_node->key;
					struct edge *e = curr_edge_map_node->value;

					if (valid_next_seg(current_path_sol->current_seg, seg)) {
						current_edge_list = scion_list_create(SCION_LIST_CUSTOM_FREE(free_solution_edge));
						ret = copy_solution_edge_list(current_edge_list, current_path_sol->edges);
						if (ret != 0) {
							goto cleanup_path_solution;
						}

						struct solution_edge *new_sol_edge = malloc(sizeof(*new_sol_edge));
						ret = init_solution_edge(new_sol_edge, e, current_path_sol->current_vertex, next_vertex, seg);
						if (ret != 0) {
							goto cleanup_path_solution;
						}

						scion_list_append(current_edge_list, new_sol_edge);

						struct path_solution *new_solution = malloc(sizeof(*new_solution));
						ret = init_path_solution(
							new_solution, current_edge_list, next_vertex, seg, current_path_sol->cost + e->weight);
						if (ret != 0) {
							goto cleanup_path_solution;
						}

						if (compare_vertices(&dst, next_vertex)) {
							scion_list_append(paths, (void *)new_solution);
						} else {
							scion_list_append(queue, (void *)new_solution);
						}
					}
					curr_edge_map_node = curr_edge_map_node->next;
				}
				curr_vertex_info_node = curr_vertex_info_node->next;
			}
		}
		free_path_solution(current_path_sol);
	}

	ret = scion_sort_path_solutions(paths);

exit:
	scion_list_free(queue);

	return ret;

cleanup_path_solution:
	free_path_solution(current_path_sol);

cleanup_edge_list:
	scion_list_free(current_edge_list);

	goto exit;
}

/*
 * ##################################################################
 * ############### Convert path_solution to scion_path ################
 * ##################################################################
 */

// Implementation of https://github.com/scionproto/scion/blob/master/private/path/combinator/graph.go#L676
static int scion_segments_to_raw_path(struct scion_list *segments, struct scion_path_raw *raw)
{
	assert(segments);
	assert(raw);

	int ret;

	struct scion_path_meta_hdr meta;
	struct scion_list *infos = scion_list_create(SCION_LIST_NO_FREE_VALUES);
	struct scion_list *hops = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	ret = scion_path_meta_hdr_init(&meta);
	if (ret != 0) {
		scion_list_free(infos);
		scion_list_free(hops);
		return ret;
	}

	uint8_t i = 0;
	struct scion_list_node *curr = segments->first;
	while (curr) {
		struct segment *curr_seg = curr->value;
		meta.seg_len[i] = (uint8_t)curr_seg->hop_fields->size;
		scion_list_append(infos, (void *)curr_seg->info_field);
		scion_list_append_all(hops, curr_seg->hop_fields);
		i++;
		curr = curr->next;
	}

	ret = scion_path_raw_init(raw, &meta, infos, hops);

	scion_list_free(infos);
	scion_list_free(hops);

	return ret;
}

// Implementation of https://github.com/scionproto/scion/blob/master/private/path/combinator/graph.go#L500
// Comments also mostly taken from the GO implementation.
static uint16_t scion_calculate_beta(struct solution_edge *sol_edge)
{
	// If this is a peer hop, we need to set beta[i] = beta[i+1]. That is, the SegID
	// accumulator must correspond to the next (in construction order) hop.
	//
	// This is because this peering hop has a MAC that chains to its non-peering
	// counterpart, the same as what the next hop (in construction order) chains to.
	// So both this and the next hop are to be validated from the same SegID
	// accumulator value: the one for the *next* hop, calculated on the regular
	// non-peering segment.
	//
	// Note that, when traversing peer hops, the SegID accumulator is left untouched for the
	// next router on the path to use.

	if (sol_edge == NULL) {
		return 0;
	}

	size_t index;
	if (sol_edge->segment->type == DOWN_SEGMENT) {
		index = sol_edge->edge->shortcut;
		if (sol_edge->edge->peer != 0) {
			index++;
		}
	} else {
		index = sol_edge->segment->segment->as_entries_length - 1; // Last entry is not used.
		if (index == sol_edge->edge->shortcut && sol_edge->edge->peer != 0) {
			index++;
		}
	}
	uint16_t beta = sol_edge->segment->segment->info.segment_id;
	for (size_t i = 0; i < index; i++) {
		struct scion_hop_entry *curr_hop_entry = &(sol_edge->segment->segment->as_entries[i]->hop_entry);
		beta = beta ^ be16toh(*(uint16_t *)curr_hop_entry->hop_field.mac);
	}
	return beta;
}

// Implementation of https://github.com/scionproto/scion/blob/master/private/path/combinator/graph.go#L313
// COMMENT: Some fields of segments have been left out. They are only used to compute metadata. As long
// as we don't want to add more metadata, we don't need them.
// COMMENT: Comments mostly copied from the GO implementation as well.

/*
 * FUNCTION: scion_path_solution_to_path
 * ---------------------
 * Converts a path_solution into a scion_path
 *
 * Arguments:
 *      - struct path_solution *list: Pointer to a path_solution.
 * 		- struct scion_path *path: Pointer to a scion_path struct into which the result will be stored.
 *
 * Returns:
 * 		- An integer status code, 0 for success or an error code as defined in error.h.
 */
static int scion_path_solution_to_path(
	struct path_solution *solution, struct scion_path *path, struct scion_topology *topology)
{
	assert(solution);
	assert(solution->edges);
	assert(path);
	assert(topology);

	int ret;

	uint16_t mtu = UINT16_MAX;
	uint16_t link_mtu = UINT16_MAX;
	int64_t expiry = INT64_MAX;
	struct scion_list *segments = scion_list_create(SCION_LIST_CUSTOM_FREE(free_segment));
	struct scion_list *all_interfaces = scion_list_create(SCION_LIST_SIMPLE_FREE);
	struct scion_list *all_as_entries = scion_list_create(SCION_LIST_NO_FREE_VALUES);

	// iterate through Solution Edges
	struct scion_list_node *curr = solution->edges->first;
	while (curr) {
		struct solution_edge *curr_sol_edge = curr->value;
		struct scion_list *hops = scion_list_create(SCION_LIST_SIMPLE_FREE);
		struct scion_list *curr_interfaces = scion_list_create(SCION_LIST_NO_FREE_VALUES);
		struct scion_list *curr_as_entries = scion_list_create(SCION_LIST_NO_FREE_VALUES);
		uint8_t min_exp_time = UINT8_MAX;

		// Segments are in construction order, regardless of whether they're
		// up or down segments. We traverse them FROM THE END. So, in reverse
		// forwarding order for down segments and in forwarding order for
		// up segments.
		// We go through each scion_as_entry, starting from the last one until we
		// find a shortcut (which can be 0, meaning the end of the segment).

		struct scion_as_entry **as_entries = curr_sol_edge->segment->segment->as_entries;
		size_t as_entries_length = curr_sol_edge->segment->segment->as_entries_length;
		size_t shortcut = curr_sol_edge->edge->shortcut;
		for (size_t i = as_entries_length; i > shortcut; i--) {
			bool is_shortcut = (i - 1 == shortcut) && (shortcut != 0); // COMMENT: Not needed if we ignore interfaces.
			bool is_peer = (i - 1 == shortcut) && (curr_sol_edge->edge->peer != 0);
			struct scion_as_entry *curr_as_entry = as_entries[i - 1];
			struct scion_hop_field *hop_field = malloc(sizeof(*hop_field));

			scion_list_append(curr_as_entries, curr_as_entry);

			if (!is_peer) {
				struct scion_hop_entry *curr_hop_entry = &(curr_as_entry->hop_entry);
				hop_field->ingress_router_alert = false; // TODO: CHeck router alerts??
				hop_field->egress_router_alert = false;
				hop_field->exp_time = curr_hop_entry->hop_field.exp_time;
				hop_field->cons_ingress = curr_hop_entry->hop_field.cons_ingress;
				hop_field->cons_egress = curr_hop_entry->hop_field.cons_egress;
				(void)memcpy(hop_field->mac, curr_hop_entry->hop_field.mac, SCION_MAC_LEN);

				link_mtu = curr_hop_entry->ingress_mtu;
			} else {
				struct scion_peer_entry *peer = curr_as_entry->peer_entries[curr_sol_edge->edge->peer - 1];
				hop_field->ingress_router_alert = false; // TODO: CHeck router alerts??
				hop_field->egress_router_alert = false;
				hop_field->exp_time = peer->hopfield.exp_time;
				hop_field->cons_ingress = peer->hopfield.cons_ingress;
				hop_field->cons_egress = peer->hopfield.cons_egress;
				(void)memcpy(hop_field->mac, peer->hopfield.mac, SCION_MAC_LEN);

				link_mtu = peer->peer_mtu;
			}

			// COMMENT: currently we handle the interfaces differently than the GO implementation.
			// We directly keep a global list and not a list per segment.
			if (hop_field->cons_egress != 0) {
				struct scion_path_interface *curr_interface = malloc(sizeof(*curr_interface));
				curr_interface->id = hop_field->cons_egress;
				curr_interface->ia = curr_as_entry->local;
				scion_list_append(curr_interfaces, (void *)curr_interface);
			}

			if (hop_field->cons_ingress != 0 && (!is_shortcut || is_peer)) {
				struct scion_path_interface *curr_interface = malloc(sizeof(*curr_interface));
				curr_interface->id = hop_field->cons_ingress;
				curr_interface->ia = curr_as_entry->local;
				scion_list_append(curr_interfaces, (void *)curr_interface);
			}

			scion_list_append(hops, (void *)hop_field);

			uint16_t as_entry_mtu = curr_as_entry->mtu;
			if (as_entry_mtu < mtu) {
				mtu = as_entry_mtu;
			}

			if (link_mtu != 0 && link_mtu < mtu) {
				mtu = link_mtu;
			}

			if (hop_field->exp_time < min_exp_time) {
				min_exp_time = hop_field->exp_time;
			}
		}

		// Put the hops in forwarding order. Needed for down segments
		// since we collected hops from the end, just like for up
		// segments.
		if (curr_sol_edge->segment->type == DOWN_SEGMENT) {
			scion_list_reverse(hops);
			scion_list_reverse(curr_interfaces);
			scion_list_reverse(curr_as_entries);
		}

		// Create segment
		struct scion_info_field *info = malloc(sizeof(*info));
		info->peer = (curr_sol_edge->edge->peer != 0);
		info->cons_dir = (curr_sol_edge->segment->type == DOWN_SEGMENT);
		info->seg_id = scion_calculate_beta(curr_sol_edge);
		// Note: The current GO implementation inconsistently uses both uint32 and int64 for the timestamp.
		// According to the proto definition
		// (https://github.com/scionproto/scion/blob/4b364f42c6e8343e5584ae2b6ddde6d2b8ef85ad/proto/control_plane/v1/seg.proto)
		// the timestamp can be a 64-bit signed integer. However, in the SCION dataplane specification of the Path Info
		// Field (https://docs.scion.org/en/latest/protocols/scion-header.html#info-field) the timestamp can only be
		// represented with 32 bits on the band. Hence, we downcast the timestamp to a 32-bit unsigned integer here.
		assert(curr_sol_edge->segment->segment->info.timestamp >= 0
			   && curr_sol_edge->segment->segment->info.timestamp < UINT32_MAX);
		info->timestamp = (uint32_t)curr_sol_edge->segment->segment->info.timestamp;

		struct segment *seg = malloc(sizeof(*seg));
		seg->info_field = info;
		seg->hop_fields = hops;

		scion_list_append(segments, (void *)seg);

		// Append Interfaces and free current list:
		scion_list_append_all(all_interfaces, curr_interfaces);
		scion_list_free(curr_interfaces);

		scion_list_append_all(all_as_entries, curr_as_entries);
		scion_list_free(curr_as_entries);

		// Expiry calculation defined in https://docs.scion.org/en/latest/protocols/scion-header.html#hop-field
		int64_t curr_expiry = (int64_t)info->timestamp + ((1 + (int64_t)min_exp_time) * (24 * 60 * 60) / 256);
		if (curr_expiry < expiry) {
			expiry = curr_expiry;
		}

		curr = curr->next;
	}

	// Set First Hop IFID
	struct scion_path_interface *intf = (struct scion_path_interface *)all_interfaces->first->value;
	ret = scion_topology_next_underlay_hop(topology, intf->id, &path->underlay_next_hop);
	if (ret != 0) {
		goto exit;
	}

	// Create scion_path_metadata
	struct scion_path_metadata *metadata = scion_path_metadata_collect(all_interfaces, all_as_entries, mtu, expiry);

	// Create raw path
	struct scion_path_raw *raw = malloc(sizeof(*raw));
	ret = scion_segments_to_raw_path(segments, raw);
	if (ret != 0) {
		goto cleanup_path_components;
	}

	// Populate scion_path
	path->path_type = SCION_PATH_TYPE_SCION;
	path->raw_path = raw;
	path->metadata = metadata;
	path->weight = (uint32_t)solution->cost;

exit:
	scion_list_free(segments);
	scion_list_free(all_as_entries);
	scion_list_free(all_interfaces);

	return ret;

cleanup_path_components:
	scion_path_metadata_free(metadata);
	scion_path_raw_free(raw);

	goto exit;
}

static bool scion_contains_loop(struct scion_path *path)
{
	if (path == NULL || path->metadata->interfaces == NULL) {
		return false;
	}

	if (path->metadata->interfaces_len < 2) {
		return false;
	}

	for (size_t i_outer = 1; i_outer < path->metadata->interfaces_len; i_outer++) {
		struct scion_path_interface *curr_intf = &path->metadata->interfaces[i_outer];

		bool duplicate_seen = false;
		for (size_t i_inner = 0; i_inner < i_outer; i_inner++) {
			struct scion_path_interface *test_intf = &path->metadata->interfaces[i_inner];

			if (test_intf->ia == curr_intf->ia) {
				if (duplicate_seen) {
					return true;
				}

				duplicate_seen = true;
			}
		}
	}

	return false;
}

// To compare paths, we use the list of ifids, which we encode in an uint16_t array.
// The first element of the array is the total number of elements in the array,
// including the size element.
static bool scion_check_duplicate_path(struct scion_list *ifids_list, scion_interface_id *ifids)
{
	int ret;
	if (ifids_list->size == 0) {
		return false;
	}

	struct scion_list_node *curr = ifids_list->first;
	while (curr) {
		uint16_t *curr_ifids = (uint16_t *)curr->value;
		if (curr_ifids == NULL) {
			continue;
		}
		if (curr_ifids[0] == ifids[0]) {
			ret = memcmp(curr_ifids, ifids, ifids[0] * sizeof(scion_interface_id));
			if (ret == 0) {
				return true;
			}
		}
		curr = curr->next;
	}
	return false;
}

static int scion_path_solution_list_to_path_list(struct scion_list *path_solutions, struct scion_list *paths,
	scion_ia src, scion_ia dst, struct scion_topology *topology, uint opt)
{
	// TODO: remove me
	(void)opt;
	assert(path_solutions);
	assert(paths);

	int ret;

	struct scion_list *ifids_list = scion_list_create(SCION_LIST_SIMPLE_FREE);
	bool duplicate;
	bool contains_loop;

	struct scion_list_node *curr = path_solutions->first;
	while (curr) {
		struct path_solution *path_sol = curr->value;
		struct scion_path *path = malloc(sizeof(*path));
		ret = scion_path_solution_to_path(path_sol, path, topology);
		if (ret != 0) {
			// scion_path_solution_to_path might fail, in that case the current path is likely garbage.
			// We just ignore it, some other conversions might have worked, giving as still a list of
			// usable paths.
			scion_path_free(path);
		} else {
			path->dst = dst;
			path->src = src;

			// Generate ifids array to check duplicate paths.
			scion_interface_id *ifids = malloc((path->metadata->interfaces_len + 1) * sizeof(scion_interface_id));
			ifids[0] = (scion_interface_id)(path->metadata->interfaces_len + 1);

			for (size_t i = 0; i < path->metadata->interfaces_len; i++) {
				struct scion_path_interface *curr_intf = &path->metadata->interfaces[i];
				ifids[i + 1] = curr_intf->id;
			}

			// Check duplicate
			duplicate = scion_check_duplicate_path(ifids_list, ifids);

			// Check loop
			contains_loop = scion_contains_loop(path);

			if (duplicate || contains_loop) {
				free(ifids);
				scion_path_free(path);
			} else {
				scion_list_append(ifids_list, ifids);
				scion_list_append(paths, path);
			}
		}
		curr = curr->next;
	}
	scion_list_free(ifids_list);
	return 0;
}

/*
 * ##################################################################
 * ##################### Complete Path building #####################
 * ##################################################################
 */

int scion_build_paths(scion_ia src, scion_ia dst, struct scion_topology *topology, struct scion_path_segment **ups,
	size_t ups_length, struct scion_path_segment **cores, size_t cores_length, struct scion_path_segment **downs,
	size_t downs_length, struct scion_list *paths, uint opt)
{
	assert(paths);

	int ret;
	struct dmg dmg;
	ret = new_dmg(ups, ups_length, cores, cores_length, downs, downs_length, &dmg);
	if (ret != 0) {
		free_dmg_internal(&dmg);
		return ret;
	}

	struct scion_list *path_solutions = scion_list_create(SCION_LIST_CUSTOM_FREE(free_path_solution));
	ret = get_paths_from_graph(&dmg, src, dst, path_solutions);
	if (ret != 0) {
		goto exit;
	}

	ret = scion_path_solution_list_to_path_list(path_solutions, paths, src, dst, topology, opt);

	// if (opt == SCION_PATH_DEBUG) {
	// 	scion_print_scion_path_list(paths);
	// }

exit:
	free_dmg_internal(&dmg);
	scion_list_free(path_solutions);
	return ret;
}

/*
 * ##################################################################
 * ######################### Debug functions ########################
 * ##################################################################
 */

#ifdef _SCION_DEBUG

static uint32_t graph_byte_size(struct dmg *g)
{
	uint32_t size = 0;
	if (g != NULL) {
		size += sizeof(dmg);

		struct dmg_node *curr_dmg_node = g->start_node;
		while (curr_dmg_node) {
			size += sizeof(dmg_node);
			if (curr_dmg_node->key != NULL) {
				size += sizeof(vertex);
			}

			struct vertex_info_node *curr_vin = curr_dmg_node->value;
			while (curr_vin) {
				size += sizeof(vertex_info_node);
				if (curr_vin->key != NULL) {
					size += sizeof(vertex);
				}

				edge_map_node *curr_emn = curr_vin->value;
				while (curr_emn) {
					size += sizeof(edge_map_node);
					if (curr_emn->value != NULL) {
						size += sizeof(edge);
					}
					curr_emn = curr_emn->next;
				}

				curr_vin = curr_vin->next;
			}

			curr_dmg_node = curr_dmg_node->next;
		}

		// Input segments
		size += g->ups_length * sizeof(struct input_segment *);
		size += g->ups_length * sizeof(struct input_segment);
		size += g->cores_length * sizeof(struct input_segment *);
		size += g->cores_length * sizeof(struct input_segment);
		size += g->downs_length * sizeof(struct input_segment *);
		size += g->downs_length * sizeof(struct input_segment);
	}
	return size;
}

static uint32_t path_solution_byte_size(path_solution *ps)
{
	uint32_t size = 0;
	if (ps != NULL) {
		size += sizeof(path_solution);

		if (ps->edges != NULL) {
			size += sizeof(scion_linked_list);
			size += ps->edges->size * sizeof(scion_linked_list_node);
			size += ps->edges->size * sizeof(solution_edge);
		}
	}
	return size;
}

#endif
