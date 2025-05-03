## Examples

This directory contains examples for using the CSNET library on UNIX-like systems. As mentioned in
the [main README](../README.md#requirements), running the examples **requires a running SCION network**. Some examples
have additional requirements documented below.

The following examples are available:

- `udp.c`: Shows how to send and receive a UDP packet. Requires a running `scripts/run-testserver.sh`.

- `paths.c`: Shows how to fetch the available paths to a specific destination in the network.

- `choose_path.c`: Shows how to send a packet over a specific path in the network. Requires a running
  `scripts/run-testserver.sh`.

- `server.c`: Shows how to implement a simple server that receives incoming packets. Run `scripts/run-testclient.sh` to
  receive a packet.

- `ping.c`: Shows how to ping a host in the network.

- `simple_quic_client.c`: Shows how to implement a simple QUIC client that uses UDP over SCION with the
  help of ngtcp2. Requires a running `scripts/run-quic-server.sh`.

- `scmp_error.c`: Shows how to catch SCMP errors when sending packets. Requires a running `scmp_error_generator.c`.

- `features.c`: Showcases some additional features of the library. Requires a running `scripts/run-testserver.sh`.