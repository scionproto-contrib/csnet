[Back to overview](/docs/main.md)

## ScionSocket
### Definition
```
typedef struct ScionSocket {
    // File descriptor for the socket
	int socket_fd;

    // Protocol used by the socket
	int protocol;

    // Pointer to local topology information
	ScionTopology *topology;

    // (Local) Source address
	ScionAddr src_addr;

    // Destination address
	ScionAddr dst_addr;

    // Pointer to path information
	ScionPath *path;

    // Next hop network address
	struct sockaddr next_hop_addr;

    // SCMP (SCION Control Message Protocol) alert flag
	bool scmp_alert;

    // Debug mode flag
	bool debug;
} ScionSocket;
```

### Description
The `ScionSocket` structure represents a SCION socket and encapsulates all the necessary details to send and receive SCION packets, including socket file descriptors, addressing information, paths, and protocol-specific settings. It acts as a central data structure for SCION networking operations.

### Members
1. `int socket_fd`
    - Description: The file descriptor associated with the socket. This is used for low-level socket operations like `send`, `recv`, or `bind`.
    - Values: 
        - `-1` indicates an invalid or uninitialized socket.
        - Otherwise, must be a valid file descriptor (non-negative).

2. `int protocol`
    - Description: Specifies the protocol used on top of SCION. Determines the payload handling and serialization/deserialization during packet processing.
    - Values:
        - `SCION_PROTO_UDP`: For UDP communications (Integer Value = 17).
        - `SCION_PROTO_SCMP`: For SCION Control Message Protocol (SCMP) (Integer Value = 202).
        - Currently does not support other values.

3. `ScionTopology *topology`
    - Description: Pointer to a [ScionTopology](/docs/structs/scion_topology.md) structure. Contains information about the local ISD-AS, control server and interfaces / border routers.

4. `ScionAddr src_addr`
    - Description: The source address of the socket, contains information such as the ISD-AS and IP address of the socket's originating endpoint.

5. `ScionAddr dst_addr`
    - Description: The destination address of the socket, used for sending data. Includes ISD-AS and IP address of the remote endpoint.
    - Notes:
        - Set explicitly or dynamically assigned during [scion_connect](/docs/functions/scion_connect.md) or [scion_sendto](/docs/functions/scion_sendto.md) operations.

6. `ScionPath *path`
    - Description: Pointer to the SCION path used for communication. It represents the path from the source to the destination in the SCION network.
    - Notes:
        - Set during [scion_connect](/docs/functions/scion_connect.md) or [scion_sendto](/docs/functions/scion_sendto.md) (if not altready set). Both functions chooses shortest path by default.
        - Can be set explicitly using [scion_set_path](/docs/functions/scion_set_path.md) if different path is desired. [scion_fetch_paths](/docs/functions/scion_fetch_paths.md) can be used to receive a list of all valid paths between a source AS and a destination AS.
    
7. `struct sockaddr next_hop_addr`
    - Description: Specifies the next-hop address used for forwarding the SCION packet, i.e. first border router the packet is sent to.

8. `bool scmp_alert`
    - Description: Indicates whether the most recent received message was an SCMP (SCION Control Message Protocol) message. Set during [scion_recv](/docs/functions/scion_recv.md) and [scion_recvfrom](/docs/functions/scion_recvfrom.md).
    - Values:
        - `true`: SCMP message received.
        - `false`: Regular message received.

9. `bool debug`
    - Description: Flag for enabling or disabling debugging features for the socket. Currently, if the debug mode is enabled, additional metadata is stored during path creation. Needed to pretty-print paths.
    - Values:
        - `true`: Debug mode enabled. Path metadata will be stored.
        - `false`: Debug mode disabled.
    - Notes:
        - If the debug mode is enabled, a paths requires significantly more memory to be stored. Could be problematic on memory constraint devices.

### Notes
- Initialized during the `scion_socket` function call.

### See also
- Structs: [ScionTopology](/docs/structs/scion_topology.md), [ScionAddr](/docs/structs/scion_addr.md), [ScionPath](/docs/structs/scion_path.md)
- Functions: [scion_socket](/docs/functions/scion_socket.md), [scion_connect](/docs/functions/scion_connect.md), [scion_send](/docs/functions/scion_send.md), [scion_sendto](/docs/functions/scion_sendto.md), [scion_recv](/docs/functions/scion_recv.md), [scion_recvfrom](/docs/functions/scion_recvfrom.md), [scion_setsockopt](/docs/functions/scion_setsockopt.md), [scion_close](/docs/functions/scion_close.md), [scion_set_path](/docs/functions/scion_set_path.md)