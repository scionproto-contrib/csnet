# Showpaths Example

This example demonstrates how to use SCION API to fetch and print available paths between two ASes in the SCION network. The code covers socket setup, path lookup, and resource cleanup using the SCION API. Below is a detailed explanation of each step in the code.

## Code Breakdown

### 1. Include SCION library
The `scion/scion.h` header file includes the complete SCION library.

```
#include "scion/scion.h"
```

### 2. Configure the Source Address
The [ScionAddr](/docs/structs/scion_addr.md) `src_addr` is used to define the source address. It consists of an IP address (in this case IPv4) and an ISD-AS number `ia`. The ISD-AS number has to match the ISD-AS number in the `topology.json` file. If you are unsure, you can set it to `0` and the library will use the ISD-AS number from the `topology.json` file. You can also use the [scion_parse_ia](/docs/functions/scion_parse_ia.md) function to parse an ISD-AS string (e.g., `"1-ff00:0:110"`) into `src_addr.ia`.

```
ScionAddr src_addr;
struct sockaddr_in *src_sockaddr = (struct sockaddr_in *)&src_addr.addr;
src_sockaddr->sin_addr.s_addr = inet_addr("<Your IP Address here>");
src_sockaddr->sin_family = AF_INET;
src_sockaddr->sin_port = htons(0);
src_addr.ia = 0x2ff0000000222;
```

### 3. Set Topology File Path
We specify the path to the topology file that describes the SCION network configuration of the local AS.
```
const char *topo_path = "../../spiffs_partition/topology.json";
```

### 4. Create a SCION socket
We allocate a [ScionSocket](/docs/structs/scion_socket.md) and initialitze it using [scion_socket](/docs/functions/scion_socket.md). For the initialization you need to provide:
- a pointer to the [ScionSocket](/docs/structs/scion_socket.md) to be initialized.
- a pointer to a [ScionAddr](/docs/structs/scion_addr.md) representing the local address.
- the protocol to be used on top of SCION, in this case UDP.
- the path to the `topology.json`.
```
ScionSocket scion_sock;
res = scion_socket(&scion_sock, &src_addr, SCION_PROTO_UDP, topo_path);
if (res != 0) {
    printf("ERROR: Socket setup failed with error code: %d", res);
    exit(res);
}
```

### 5. Fetch the paths
First, we define the destination ISD-AS and create a [ScionLinkedList](/docs/structs/scion_linked_list.md) `paths` to store the fetched paths. Then we fetch the paths using [scion_fetch_paths](/docs/functions/scion_fetch_paths.md). It important to set `SCION_PATH_DEBUG`, as otherwise the metadata of the paths will not be stored, making it impossible to pretty print them.
```
ScionIA dst_ia = 0x1ff0000000133;

ScionLinkedList *paths = scion_list_create();
res = scion_fetch_paths(scion_sock.topology, src_addr.ia, dst_ia, paths, SCION_PATH_DEBUG);
if (res != 0) {
	printf("ERROR: Failed to fetch paths with error code: %d\n", res);
}
```

### 6. Display paths
The `scion_print_scion_path_list` pretty prints the paths to stdout.
```
printf("\nPath lookup from ");
scion_print_ia(src_addr.ia);
printf(" to ");
scion_print_ia(dst_ia);
printf("\n");
scion_print_scion_path_list(paths);
```

### 7. Clean-up
In a last step, the paths are free'd, the socket closed and internal structs are also freed.
```
scion_free_path_list(paths);

scion_close(&scion_sock);
scion_socket_free_internal(&scion_sock);
```