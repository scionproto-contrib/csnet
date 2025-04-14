[Back to overview](/docs/main.md)

## ScionAddr
### Definition
```
typedef struct ScionAddr {
    // Standard POSIX socket address
	struct sockaddr addr;

    // Length of the socket address
	socklen_t addr_len;

    // SCION ISD-AS number
	ScionIA ia;
} ScionAddr;
```

### Description
The `ScionAddr` structure encapsulates addressing information required to address an end host in a SCION network. It includes details such as a socket address and SCION-specific ISD-AS number.

### Members
1. `struct sockaddr addr`
    - Description: Standard POSIX socket address, representing the network-layer address (IPv4 or IPv6) associated with the SCION address. Contains either a sockaddr_in (IPv4) or sockaddr_in6 (IPv6) structure.
    - Notes:
        - Currently only IPv4 or IPv6 is supported, i.e., the address familiy needs to be `AF_INET` or `AF_INET6`.

2. `socklen_t addr_len`
    - Description: Specifies the length of the `addr` member.

2. `ScionIA ia`
    - Description: Represents the ISD-AS number of the AS in which the end host, which is represented by this address, is located.

### See also
- Types: [ScionIA](/docs/types.md#scionia)
- Structs: [ScionSocket](/docs/structs/scion_socket.md), [ScionAddrStorage](/docs/structs/scion_addr_storage.md)
- Functions: [scion_socket](/docs/functions/scion_socket.md), [scion_connect](/docs/functions/scion_connect.md), [scion_send](/docs/functions/scion_send.md), [scion_sendto](/docs/functions/scion_sendto.md), [scion_recv](/docs/functions/scion_recv.md)