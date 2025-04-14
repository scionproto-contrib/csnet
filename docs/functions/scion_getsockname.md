[Back to overview](/docs/main.md)

## scion_getsockname
### Function signature:
```int scion_getsockname(ScionSocket *scion_sock, ScionAddr *addr);```

### Description
The `scion_getsockname` function retrieves the local address associated with a given [ScionSocket](/docs/structs/scion_socket.md) and stores it in the provided [ScionAddr](/docs/structs/scion_addr.md) structure.

### Parameters

- `ScionSocket *scion_sock`: Pointer to a [ScionSocket](/docs/structs/scion_socket.md) structure. Must not be `NULL`.
- `ScionAddr *src_addr`: Pointer to a [ScionAddr](/docs/structs/scion_addr.md) structure into which the local address associated with the socket will be stored. Must not be `NULL`.

### Return values
The function returns an integer value indicating the status of the socket initialization:

- `0`: Success 
- `< 0`: Error codes as specified in `error.h`

### Notes

### Usage example

### See also
- Structs:
[ScionSocket](/docs/structs/scion_socket.md), [ScionAddr](/docs/structs/scion_addr.md)
- Functions: [scion_connect](/docs/functions/scion_connect.md), [scion_send](/docs/functions/scion_send.md), [scion_sendto](/docs/functions/scion_sendto.md), [scion_recv](/docs/functions/scion_recv.md), [scion_recvfrom](/docs/functions/scion_recvfrom.md), [scion_setsockopt](/docs/functions/scion_setsockopt.md), [scion_close](/docs/functions/scion_close.md), [scion_set_path](/docs/functions/scion_set_path.md)