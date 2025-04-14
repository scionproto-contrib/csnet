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

#include <sys/socket.h>

#include "esp_idf_version.h"
#include "esp_netif.h"
#include "esp_spiffs.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "led_strip.h"
#include "nvs_flash.h"

#if ESP_IDF_VERSION <= ESP_IDF_VERSION_VAL(5, 1, 0)
#include "lwip/apps/sntp.h"
#else
#include "esp_netif_sntp.h"
#endif

#include "protocol_examples_common.h"

#include "scion/scion.h"

#include "testing.h"

// HEAP DEBUGGING
// #include "esp_heap_trace.h"
// #define NUM_RECORDS 2000
// static heap_trace_record_t trace_record[NUM_RECORDS];

#define BLINK_GPIO 48
static led_strip_handle_t led_strip;

// Taken from BLINK example
// https://github.com/espressif/esp-idf/blob/dbce23f8a449eb436b0b574726fe6ce9a6df67cc/examples/get-started/blink/main/blink_example_main.c#L44
static void configure_led(void)
{
	/* LED strip initialization with the GPIO and pixels number*/
	led_strip_config_t strip_config = {
		.strip_gpio_num = BLINK_GPIO,
		.max_leds = 1, // at least one LED on board
	};
	led_strip_rmt_config_t rmt_config = {
		.resolution_hz = 10 * 1000 * 1000, // 10MHz
		.flags.with_dma = false,
	};
	ESP_ERROR_CHECK(led_strip_new_rmt_device(&strip_config, &rmt_config, &led_strip));
	/* Set all LED off to clear all pixels */
	led_strip_clear(led_strip);
}

static void example_task(void *args)
{
	int ret;

	esp_netif_t *netif;
	netif = get_example_netif_from_desc(EXAMPLE_NETIF_DESC_STA);
	ESP_ERROR_CHECK(netif == NULL ? ESP_FAIL : ESP_OK);
	esp_netif_ip_info_t ip_info;
	ESP_ERROR_CHECK(esp_netif_get_ip_info(netif, &ip_info));

	ScionTopology *topology;
	ret = scion_topology_from_path(&topology, "/spiffs/topology.json");
	if (ret != 0) {
		printf("ERROR: Topology init failed with error code: %d\n", ret);
		goto exit;
	}

	struct scion_network *network;
	ret = scion_network(&network, topology);
	if (ret != 0) {
		printf("ERROR: Network init failed with error code: %d\n", ret);
		goto cleanup_topology;
	}

	struct sockaddr_in src_addr;
	src_addr.sin_family = AF_INET;
	src_addr.sin_port = htons(0);
	src_addr.sin_addr.s_addr = ip_info.ip.addr;
	socklen_t src_addr_len = sizeof(src_addr);

	// Set network source address to be used explicitly because it cannot be automatically determined on ESP32
	ret = scion_network_set_addr(network, (struct sockaddr *)&src_addr, src_addr_len);
	if (ret != 0) {
		printf("ERROR: Setting network address failed with error code: %d\n", ret);
		goto cleanup_network;
	}

	struct sockaddr_in6 dst_addr;
	dst_addr.sin6_family = AF_INET6;
	dst_addr.sin6_port = htons(31000);
	inet_pton(AF_INET6, "fd00:f00d:cafe::7f00:55", &dst_addr.sin6_addr);
	scion_ia dst_ia = 0x2ff0000000222;

	struct scion_socket *scion_sock;
	ret = scion_socket(&scion_sock, SCION_PROTO_UDP, network);
	if (ret != 0) {
		printf("ERROR: Socket setup failed with error code: %d\n", ret);
		led_strip_set_pixel(led_strip, 0, 1, 0, 0);
		led_strip_refresh(led_strip);
		goto cleanup_network;
	}

	bool debug = 1;
	ret = scion_setsockopt(scion_sock, SOL_SOCKET, SCION_SO_DEBUG, &debug, sizeof(debug));
	if (ret != 0) {
		printf("ERROR: Setting SCION_SO_DEBUG failed: %d\n", ret);
		goto cleanup_socket;
	}

	struct timeval timeout;
	timeout.tv_sec = 1;
	timeout.tv_usec = 0;
	ret = scion_setsockopt(scion_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
	if (ret != 0) {
		printf("ERROR: Setting SO_RCVTIMEO failed: %d\n", ret);
		goto cleanup_socket;
	}

	ret = scion_connect(scion_sock, (struct sockaddr *)&dst_addr, sizeof(dst_addr), dst_ia);
	if (ret != 0) {
		printf("ERROR: Socket connect failed with error code: %d\n", ret);
		goto cleanup_socket;
	}

	scion_ia src_ia;
	ret = scion_getsockname(scion_sock, (struct sockaddr *)&src_addr, &src_addr_len, &src_ia);
	if (ret != 0) {
		printf("ERROR: Socket getname failed with error code: %d\n", ret);
		goto cleanup_socket;
	}

	printf("\n\n");

	// ### Showpaths ###
	ScionLinkedList *paths = scion_list_create();
	ret = scion_fetch_paths(network, dst_ia, paths, SCION_PATH_DEBUG);
	if (ret != 0) {
		printf("ERROR: Failed to fetch paths with error code: %d\n", ret);
	} else {
		printf("\n\nPath lookup from ");
		scion_print_ia(src_ia);
		printf(" to ");
		scion_print_ia(dst_ia);
		printf("\n");
		scion_print_scion_path_list(paths);
	}
	scion_free_path_list(paths);

	// ### PING ###
	printf("\n\n");
	scion_ping((struct sockaddr *)&dst_addr, sizeof(dst_addr), dst_ia, network, 3, 0, timeout );

	// ### Send and Receive ###
	char tx_buf[] = "Hello, SCION!";
	ret = scion_send(scion_sock, tx_buf, sizeof tx_buf - 1, /* flags: */ 0);
	if (ret < 0) {
		printf("ERROR: Send failed with error code: %d\n", ret);
		led_strip_set_pixel(led_strip, 0, 1, 0, 0);
		led_strip_refresh(led_strip);
		goto cleanup_socket;
	}
	printf("[Sent %d bytes]: \"%s\"\n", ret, tx_buf);

	vTaskDelay(200 / portTICK_PERIOD_MS);

	// char rx_buf[sizeof tx_buf];
	char rx_buf[200];
	ret = scion_recv(scion_sock, &rx_buf, sizeof rx_buf - 1, /* flags: */ 0);
	if (ret < 0) {
		printf("ERROR: Receive failed with error code: %d\n", ret);
		led_strip_set_pixel(led_strip, 0, 1, 0, 0);
		led_strip_refresh(led_strip);
		goto cleanup_socket;
	}
	rx_buf[ret] = '\0';

	// ### Set Path (and resent UDP) ###
	paths = scion_list_create();
	ret = scion_fetch_paths(network, dst_ia, paths, SCION_PATH_DEBUG);
	if (ret != 0) {
		printf("ERROR: Failed to fetch paths with error code: %d\n", ret);
	}

	bool found = false;
	ScionPath *curr_path;
	while (!found) {
		curr_path = (ScionPath *)scion_list_pop(paths);
		if (curr_path == NULL) {
			printf("ERROR: Failed to find path meeting criteria\n");
			goto cleanup_socket;
		}
		if (curr_path->weight == 8 && curr_path->metadata->mtu == 1400) {
			found = true;
		} else {
			scion_free_scion_path(curr_path);
		}
	}
	scion_free_path_list(paths);

	// Send and receive
	char tx_buf2[] = "Hello, Scion! (using sendto with a specific path)";
	printf("\nUsing Path:\n");
	scion_print_scion_path(curr_path);
	ret = scion_sendto(scion_sock, tx_buf2, sizeof tx_buf2 - 1, /* flags: */ 0, (struct sockaddr *)&dst_addr, sizeof(dst_addr), dst_ia, curr_path);
	if (ret < 0) {
		printf("ERROR: Send failed with error code: %d\n", ret);
		led_strip_set_pixel(led_strip, 0, 1, 0, 0);
		led_strip_refresh(led_strip);
		goto cleanup_path;
	}
	printf("[Sent %d bytes]: \"%s\"\n", ret, tx_buf2);

	vTaskDelay(200 / portTICK_PERIOD_MS);

	ret = scion_recv(scion_sock, &rx_buf, sizeof rx_buf - 1, /* flags: */ 0);
	if (ret < 0) {
		printf("ERROR: Receive failed with error code: %d\n", ret);
		led_strip_set_pixel(led_strip, 0, 1, 0, 0);
		led_strip_refresh(led_strip);
		goto cleanup_path;
	}
	rx_buf[ret] = '\0';

	printf("\n\n");

	scion_run_tests();

	printf("Done.\n");

	led_strip_set_pixel(led_strip, 0, 0, 1, 0);
	led_strip_refresh(led_strip);

cleanup_path:
	scion_free_scion_path(curr_path);

cleanup_socket:
	scion_close(scion_sock);

cleanup_network:
	scion_network_free(network);

cleanup_topology:
	scion_topology_free(topology);

exit:
	vTaskDelete(NULL);
}

void app_main(void)
{
	ESP_ERROR_CHECK(nvs_flash_init());
	ESP_ERROR_CHECK(esp_netif_init());
	ESP_ERROR_CHECK(esp_event_loop_create_default());

	configure_led();
	led_strip_set_pixel(led_strip, 0, 0, 0, 1);
	led_strip_refresh(led_strip);

	/* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
	 * See "Establishing Wi-Fi or Ethernet Connection" section in
	 * examples/protocols/README.md for more information about this function.
	 */
	ESP_ERROR_CHECK(example_connect());

	// mount SPIFFS partition
	// clang-format off
	esp_vfs_spiffs_conf_t spiffs_conf = {
		.base_path = "/spiffs", 
		.partition_label = NULL, 
		.max_files = 1, 
		.format_if_mount_failed = false
	};
	// clang-format on

	ESP_ERROR_CHECK(esp_vfs_spiffs_register(&spiffs_conf));

	(void)xTaskCreate(&example_task, "example_task",
		/* stackDepth: */ 1024 * 32,
		/* parameters: */ NULL,
		/* priority: */ 5,
		/* createdTask: */ NULL);
}
