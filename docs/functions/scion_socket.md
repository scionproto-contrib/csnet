[Back to overview](/docs/main.md)

## scion_socket
### Function signature:
```int scion_socket(ScionSocket *scion_sock, ScionAddr *src_addr, int protocol);```

### Description
The `scion_socket` function initializes and configures a SCION socket structure. It creates a SCION socket for communication and assigns its topology and associated parameters.

### Parameters

- `ScionSocket *scion_sock`: Pointer to a [ScionSocket](/docs/structs/scion_socket.md) structure where the socket details and configuration will be stored. Must not be `NULL`.
- `ScionAddr *src_addr`: Pointer to a [ScionAddr](/docs/structs/scion_addr.md) structure containing the source address to associate with the socket. Must not be `NULL`.
- `int protocol`: Specifies the protocol type for the SCION socket (e.g., custom protocol identifiers). Currently supports `SCION_PROTO_UDP` (17) and `SCION_PROTO_SCMP` (202) for UDP and SCMP respectively.

### Return values
The function returns an integer value indicating the status of the socket initialization:

- `0`: Success 
- `< 0`: Error codes as specified in `error.h`

### Notes
- This is a wrapper around the standard POSIX `connect` function, tailored for SCION socket abstractions.

### Usage example

### See also
- Structs:
[ScionSocket](/docs/structs/scion_socket.md), [ScionAddr](/docs/structs/scion_addr.md)
- Functions: [scion_connect](/docs/functions/scion_connect.md), [scion_send](/docs/functions/scion_send.md), [scion_sendto](/docs/functions/scion_sendto.md), [scion_recv](/docs/functions/scion_recv.md), [scion_recvfrom](/docs/functions/scion_recvfrom.md), [scion_setsockopt](/docs/functions/scion_setsockopt.md), [scion_close](/docs/functions/scion_close.md), [scion_set_path](/docs/functions/scion_set_path.md)