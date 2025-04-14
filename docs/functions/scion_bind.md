[Back to overview](/docs/main.md)

## scion_bind
### Function signature:
```int scion_bind(ScionSocket *scion_sock, ScionAddr *addr);```

### Description
The `scion_bind` function associates a SCION socket with a specific local address.

### Parameters
- `ScionSocket *scion_sock`: Pointer to the [ScionSocket](/docs/structs/scion_socket.md) structure representing the socket to bind. Must not be `NULL` and the socket's file descriptor must be valid.
- `ScionAddr *addr`: Pointer to the [ScionAddr](/docs/structs/scion_addr.md) structure specifying the address to bind the socket to. Must not be `NULL` and the address must be properly initialized before calling the function.

### Return values
The function returns an integer indicating the result of the operation:
- `0`: Success, the socket was successfully bound to the address.
- `< 0`: Error codes as specified in `error.h`

### Notes
- `Error Handling`: Errors encountered by the POSIX `bind` function (e.g., address already in use, invalid address) are returned to the caller.
- This is a wrapper around the standard POSIX `bind` function, tailored for SCION socket abstractions.

### Usage example

### See also
- Structs:
[ScionSocket](/docs/structs/scion_socket.md), [ScionAddr](/docs/structs/scion_addr.md)
- Functions: [scion_socket](/docs/functions/scion_socket.md), [scion_connect](/docs/functions/scion_connect.md), [scion_send](/docs/functions/scion_send.md), [scion_sendto](/docs/functions/scion_sendto.md), [scion_recv](/docs/functions/scion_recv.md), [scion_recvfrom](/docs/functions/scion_recvfrom.md), [scion_setsockopt](/docs/functions/scion_setsockopt.md), [scion_close](/docs/functions/scion_close.md)