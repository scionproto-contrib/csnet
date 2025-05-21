# Getting Started

This guide will help you get started using the CSNET library in your C application. You can either follow this
step-by-step walkthrough or refer to the example programs in the `./examples` directory. The complete API documentation
is available [here](https://scionproto-contrib.github.io/csnet/scion_8h.html).

In this guide, we will show how to connect to the **locally running** test network in `./network/scion-testnet` that you
should have already set up. In case you want to connect to a different SCION network, you have to provide your own
`topology.json` in the instructions below.

> **Note**: Ensure that you have built and installed the CSNET library and that a **local** SCION network is running, as
> described in the [main README](../README.md#building-and-installation).

### Including the Header

To use CSNET in your C application, include the following public header:

```C
#include <scion/scion.h>
```

### Creating the Topology and Network

In order for the library to be able to connect to the SCION network you first have to create a `scion_topology`:

```C
struct scion_topology *topology;
int ret = scion_topology_from_file(&topology, "path/to/your/topology.json");
```

The `topology.json` file should contain the topology information of your local AS. If you are running the local SCION
network (locally running test network in `./network/scion-testnet`) you can copy this file from
`./network/scion-testnet/topos/default/ASXXX_X_XXX/topology.json` where `XXX_X_XXX`
should be replaced with the AS number of the AS you want your application to be in. For example, the examples in
`./examples` all use the local AS `ASff00_0_112`. In case you want to connect to a different SCION network than the
local test network you have to
provide your own `topology.json`.

Check the return code (`ret`) to ensure the topology was created successfully. A non-zero value indicates an error —
refer to the API documentation for error code explanations.

Once the topology is initialized, create a `scion_network` from the topology:

```C
struct scion_network *network;
ret = scion_network(&network, topology);
```

This network object will be used to create new SCION sockets that are able to communicate with the SCION network.

### Creating a Socket

The CSNET library currently supports UDP and SCMP (SCION’s equivalent of ICMP) sockets. Similarly to BSD sockets, a
SCION socket can be created as follows:

```C
struct scion_socket *scion_sock;
ret = scion_socket(&scion_sock, SCION_AF_IPV4, SCION_PROTO_UDP, network);
```

The socket is created by providing the local address family (in this case `SCION_AF_IPV4`), the socket protocol (in this
cas `SCION_PROTO_UDP`) and the local network.

#### Socket Operations

Similarly to BSD sockets, SCION sockets can:

- `scion_bind()` — bind the socket to a local address
- `scion_connect()` — connect the socket to a remote address
- `scion_send()`, `scion_recv()` — send/receive data over a connected socket
- `scion_sendto()` — send data to a specific destination and path
- `scion_recvfrom()` — receive data along with additional information such as sender and incoming path

#### Key Differences from BSD Sockets

Some of the key differences between SCION sockets and BSD sockets are:

- SCION sockets require topology information (via the `scion_network` object).
- Sending packets requires not only the destination IP address and port but also the destination IA (`scion_ia`). The IA
  is a combination of the ISD identifier and the AS number of an AS (e.g. `2-ff00:0:222`). The IA can be found in the
  `isd_as` field of the `topology.json` of an AS.
- When sending data to a destination host, the path the packet should take through the SCION network can be
  explicitly defined. Available paths to a specific destination AS can be retrieved with `scion_fetch_paths()`.

### Freeing resources

Be sure to free all dynamically allocated resources when they are no longer needed:

- use `scion_close()` to free sockets
- use the appropriate freeing functions for `scion_topology`, `scion_network`, etc.

### Linking the library

When linking your application, link against the following libraries:

- `libnghttp2.a`
- `libprotobuf-c.a`
- `libscion.a`

These libraries are produced during the CSNET installation process.

