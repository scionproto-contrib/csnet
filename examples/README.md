## Examples

This directory contains examples for using the csnet library on UNIX-like systems. As mentioned in
the [main README](../README.md#requirements), running the examples **requires a running SCION network**. Some examples
have additional requirements documented below.

The following examples are available:

- `udp.c`: Shows how to send and receive a UDP packet. Requires a running `scripts/run-testserver.sh`.

- `paths.c`: Shows how to fetch the available paths to a specific destination in the network.

- `choose_path.c`: Shows how to send a packet over a specific path in the network. Requires a running
  `scripts/run-testserver.sh`.

- `server.c`: Shows how to implement a simple server that receives incoming packets. Run `scripts/run-testclient.sh` to
  receive a packet.

- `simple_quic_client.c`: Shows how to use the QUIC library (`scion/scion_quic.h`, see
  [docs/quic.md](../docs/quic.md)): sends a message on a QUIC stream and prints the answer. Requires `-DBUILD_QUIC=ON`
  and a running `scripts/run-quic-server.sh`. Also runs on the ESP32 (see [esp32/README.md](../esp32/README.md)).

- `scmp_error.c`: Shows how to catch and decode SCMP errors when sending packets. Requires a running `scmp_error_generator.c`.

- `policy.c`: Shows how to use a custom path policy. Requires a running `scripts/run-testserver.sh`.

- `selector.c`: Shows how to implement a custom path selector that sends each packet over the next path and skips the
  paths that SCMP errors reported as down. Requires a running `scripts/run-testserver.sh`.

- `bootstrapper.c`: Shows how to use the bootstrapper. Requires you to be in a network where DNS-bootstrapping is
  configured, e.g. in the ETHZ network (via VPN for example).

- `messages.c`: Shows how to use send and receive messages. Requires a running `scripts/run-testserver.sh`.

- `timestamps.c`: Shows how to get the timestamps of a sent and a received packet. Run it with the name of a network
  interface to try hardware timestamps.

- `features.c`: Showcases some additional features of the library. Requires a running `scripts/run-testserver.sh`.