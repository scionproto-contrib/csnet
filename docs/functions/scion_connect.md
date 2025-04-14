[Back to overview](/docs/main.md)

## scion_connect
### Function signature:
```int scion_connect(ScionSocket *scion_sock, ScionAddr *dst_addr);```
### Description
The `scion_connect` function connects a SCION socket to a destination address by determining the path and setting the appropriate next-hop information.

### Parameters
- `ScionSocket *scion_sock`: Pointer to a [ScionSocket](/docs/structs/scion_socket.md) structure, representing the SCION socket that will be connected to the destination. Must not be `NULL` and must have been successfully initialized using `scion_socket` before using with `scion_connect`.
- `ScionAddr *dst_addr`: Pointer to a [ScionAddr](/docs/structs/scion_addr.md) structure representing the destination address. Must not be `NULL`.

### Return values
The function returns an integer value indicating the status of the connection attempt:

- `0`: Success 
- `< 0`: Error codes as specified in `error.h`

### Notes
- This is a wrapper around the standard POSIX `connect` function, tailored for SCION socket abstractions.

### Usage example

### See also
- Structs:
[ScionSocket](/docs/structs/scion_socket.md), [ScionAddr](/docs/structs/scion_addr.md)
- Functions: [scion_socket](/docs/functions/scion_socket.md), [scion_send](/docs/functions/scion_send.md), [scion_sendto](/docs/functions/scion_sendto.md), [scion_recv](/docs/functions/scion_recv.md), [scion_recvfrom](/docs/functions/scion_recvfrom.md), [scion_setsockopt](/docs/functions/scion_setsockopt.md), [scion_close](/docs/functions/scion_close.md)