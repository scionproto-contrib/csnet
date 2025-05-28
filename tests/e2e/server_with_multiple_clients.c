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

#include <arpa/inet.h>
#include <assert.h>
#include <pthread.h>
#include <scion/scion.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define NUM_CLIENTS 4

const char *topo_base_path;

struct host {
	char *topo_path;
	struct sockaddr *server_addr;
	socklen_t server_addr_len;
	scion_ia server_ia;

	pthread_t thread;
};

void *server_fn(void *arg)
{
	struct host *host = arg;

	struct scion_topology *topology;
	struct scion_network *network;

	char topo_path[strlen(topo_base_path) + strlen(host->topo_path) + 1];
	strcpy(topo_path, topo_base_path);
	strcat(topo_path, host->topo_path);

	assert(scion_topology_from_file(&topology, topo_path) == 0);
	pthread_cleanup_push((void (*)(void*))scion_topology_free, topology);

	assert(scion_network(&network, topology) == 0);
	pthread_cleanup_push((void (*)(void*))scion_network_free, network);

	struct scion_socket *scion_sock;

	assert(scion_socket(&scion_sock, scion_network_get_local_addr_family(network), SCION_PROTO_UDP, network) == 0);
	pthread_cleanup_push((void (*)(void*))scion_close, scion_sock);
	assert(scion_bind(scion_sock, host->server_addr, host->server_addr_len) == 0);

	printf("Started server\n");

	while (1) {
		struct sockaddr_storage client_addr;
		socklen_t client_addr_len = sizeof(client_addr);
		scion_ia client_ia;
		struct scion_path *path;

		char buffer[200] = { 0 };

		assert(scion_recvfrom(scion_sock, buffer, sizeof(buffer) - 1, 0, (struct sockaddr *)&client_addr,
				   &client_addr_len, &client_ia, &path)
			   > 0);

		printf("Received message: %s\n", buffer);

		assert(scion_path_reverse(path) == 0);

		// Respond to the client
		const char *response = "Acknowledged";
		assert(scion_sendto(scion_sock, response, strlen(response), 0, (struct sockaddr *)&client_addr, client_addr_len,
				   client_ia, path)
			   > 0);

		scion_path_free(path);
	}

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
}

void *client_fn(void *arg)
{
	struct host *client = arg;

	struct scion_topology *topology;
	struct scion_network *network;

	char topo_path[strlen(topo_base_path) + strlen(client->topo_path) + 1];
	strcpy(topo_path, topo_base_path);
	strcat(topo_path, client->topo_path);

	assert(scion_topology_from_file(&topology, topo_path) == 0);
	pthread_cleanup_push((void (*)(void*))scion_topology_free, topology);

	assert(scion_network(&network, topology) == 0);
	pthread_cleanup_push((void (*)(void*))scion_network_free, network);

	struct scion_socket *scion_sock;

	assert(scion_socket(&scion_sock, scion_network_get_local_addr_family(network), SCION_PROTO_UDP, network) == 0);
	pthread_cleanup_push((void (*)(void*))scion_close, scion_sock);

	int ret = scion_connect(scion_sock, client->server_addr, client->server_addr_len, client->server_ia);
	assert(ret == 0);

	char message[100];
	snprintf(message, sizeof(message), "Hello from client %ld", client->thread);
	char response[200] = { 0 };

	assert(scion_send(scion_sock, message, sizeof(message), 0));

	int n = scion_recv(scion_sock, response, sizeof(response) - 1, 0);
	assert(n > 0);

	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);
	pthread_cleanup_pop(1);

	return NULL;
}

int main(int argc, char *argv[])
{
	topo_base_path = getenv("TOPO_BASE_PATH");

	struct host clients[NUM_CLIENTS] = { (struct host){ .topo_path = "/ASff00_0_133/topology.json" },
		(struct host){ .topo_path = "/ASff00_0_112/topology.json" },
		(struct host){ .topo_path = "/ASff00_0_220/topology.json" },
		(struct host){ .topo_path = "/ASff00_0_222/topology.json" } };

	struct sockaddr_in server_addr;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.100");
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(31002);
	scion_ia server_ia;
	assert(scion_ia_parse("1-ff00:0:133", strlen("1-ff00:0:133"), &server_ia) == 0);

	struct host server = { .topo_path = "/ASff00_0_133/topology.json",
		.server_addr = (struct sockaddr *)&server_addr,
		.server_addr_len = sizeof(server_addr) };

	pthread_t server_thread;
	assert(pthread_create(&server_thread, NULL, server_fn, &server) == 0);

	sleep(10); // Give the server some time to start

	for (size_t i = 0; i < NUM_CLIENTS; i++) {
		clients[i].server_addr = (struct sockaddr *)&server_addr;
		clients[i].server_addr_len = sizeof(server_addr);
		clients[i].server_ia = server_ia;
		assert(pthread_create(&clients[i].thread, NULL, client_fn, &clients[i]) == 0);
	}

	for (size_t i = 0; i < NUM_CLIENTS; i++) {
		assert(pthread_join(clients[i].thread, NULL) == 0);
	}

	assert(pthread_cancel(server_thread) == 0);
}
