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

#include <arpa/inet.h>
#include <benchmark/benchmark.h>
#include <cstdint>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

extern "C" {
#include "scion/scion.h"
}

// Each round sends a packet over loopback and receives it in the same thread, so it measures the cost of one send and
// one receive, without the scheduling of a second thread. The packets stay in the local AS, so they have an empty path
// and need neither a control service nor a border router. udp_send_recv is the same with plain UDP sockets, the
// difference is the cost of SCION.

static const int SIZES[] = { 64, 512, 1400 };

static void scion_send_recv(benchmark::State &state)
{
	struct scion_topology *topology = nullptr;
	struct scion_network *network = nullptr;
	struct scion_socket *sender = nullptr;
	struct scion_socket *receiver = nullptr;
	struct sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	socklen_t addr_len = sizeof(addr);
	// A lost packet fails the benchmark instead of blocking it
	struct timeval timeout = { 1, 0 };

	if (scion_topology_from_file(&topology, BENCH_TOPOLOGY) != 0 || scion_network(&network, topology) != 0
		|| scion_socket(&sender, SCION_AF_INET, SCION_SOCK_DGRAM, SCION_PROTO_UDP, network) != 0
		|| scion_socket(&receiver, SCION_AF_INET, SCION_SOCK_DGRAM, SCION_PROTO_UDP, network) != 0
		|| scion_bind(sender, (struct sockaddr *)&addr, sizeof(addr)) != 0
		|| scion_bind(receiver, (struct sockaddr *)&addr, sizeof(addr)) != 0
		|| scion_getsockname(receiver, (struct sockaddr *)&addr, &addr_len, nullptr) != 0
		|| scion_setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
		state.SkipWithError("cannot set up the SCION sockets");
	} else {
		scion_ia ia = scion_topology_get_local_ia(topology);
		size_t size = (size_t)state.range(0);
		uint8_t data[1500] = { 0 };
		uint8_t buf[1500];

		for (auto _ : state) {
			if (scion_sendto(sender, data, size, 0, (struct sockaddr *)&addr, addr_len, ia, nullptr) != (ssize_t)size
				|| scion_recv(receiver, buf, sizeof(buf), 0) != (ssize_t)size) {
				state.SkipWithError("cannot send or receive a packet");
				break;
			}
		}
		state.SetItemsProcessed(state.iterations());
		state.SetBytesProcessed(state.iterations() * state.range(0));
	}

	if (receiver) {
		scion_close(receiver);
	}
	if (sender) {
		scion_close(sender);
	}
	scion_network_free(network);
	scion_topology_free(topology);
}
BENCHMARK(scion_send_recv)->ArgsProduct({ { std::begin(SIZES), std::end(SIZES) } });

static void udp_send_recv(benchmark::State &state)
{
	int sender = socket(AF_INET, SOCK_DGRAM, 0);
	int receiver = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	socklen_t addr_len = sizeof(addr);
	struct timeval timeout = { 1, 0 };

	if (sender < 0 || receiver < 0 || bind(receiver, (struct sockaddr *)&addr, sizeof(addr)) != 0
		|| getsockname(receiver, (struct sockaddr *)&addr, &addr_len) != 0
		|| setsockopt(receiver, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
		state.SkipWithError("cannot set up the UDP sockets");
	} else {
		size_t size = (size_t)state.range(0);
		uint8_t data[1500] = { 0 };
		uint8_t buf[1500];

		for (auto _ : state) {
			if (sendto(sender, data, size, 0, (struct sockaddr *)&addr, addr_len) != (ssize_t)size
				|| recv(receiver, buf, sizeof(buf), 0) != (ssize_t)size) {
				state.SkipWithError("cannot send or receive a packet");
				break;
			}
		}
		state.SetItemsProcessed(state.iterations());
		state.SetBytesProcessed(state.iterations() * state.range(0));
	}

	if (receiver >= 0) {
		close(receiver);
	}
	if (sender >= 0) {
		close(sender);
	}
}
BENCHMARK(udp_send_recv)->ArgsProduct({ { std::begin(SIZES), std::end(SIZES) } });
