## Examples

This directory contains examples for using SCION on the ESP32 and on Unix systems. All examples require the SCION test network, see [Getting started](/docs/getting-started.md).

The following 5 examples are available:
- `ShowPaths`: Fetch paths between the local AS and specified destination AS and print them. Unix version: `examples/unix/unix_paths_example_main.c`, ESP32 version: `examples/esp32/esp32_paths_example_main.c`. [Code Breakdown](/docs/examples/paths_example.md) (for Unix version.)

- `Ping`: Ping a SCION-enabled host using SCMP echo requests. Unix version: `examples/unix/unix_ping_example_main.c`, ESP32 version: `examples/esp32/esp32_ping_example_main.c`.

- `UDP client`: Send a message using UDP over SCION to a server and print the response. Unix version: `examples/unix/unix_udp_example_main.c`, ESP32 version: `examples/esp32/esp32_udp_example_main.c`.

- `Set Path`: Similar to the `UDP cleint` example, but choses a specific path to send the UDP packet. Unix version: `examples/unix/unix_set_path_example_main.c`, ESP32 version: `examples/esp32/esp32_set_path_example_main.c`.

- `Server`: A UDP server which responds to incomming messages with the same message. It sends the response over the same path as the original message. Unix version: `examples/unix/unix_server_example_main.c`, ESP32 version: `examples/esp32/esp32_server_example_main.c`.