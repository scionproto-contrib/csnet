[Back to overview](/docs/main.md)

## scion_sendto
### Function signature:
```int scion_sendto(ScionSocket *scion_sock, const void *message, size_t length, int flags, ScionAddr *dst_addr, ScionPath *path);```

### Description
The `scion_sendto` function sends a message through a SCION socket to a specified destination address. It constructs a SCION packet, including headers and payload, serializes it, and sends it using a SCION path.

### Parameters
- `ScionSocket *scion_sock`: Pointer to a [ScionSocket](/docs/structs/scion_socket.md) structure. This represents the SCION socket to use for sending the message. Must not be `NULL` and must have a valid destination address, source address, and path.
- `const void *message`: Pointer to the message data to be sent. Can be `NULL` only if length is 0.
- `size_t length`: The length of the message in bytes. If length is greater than 0, message must not be `NULL`.
- `int flags`: Flags to pass to the underlying `sendto` call of the underlying POSIX socket.
- `ScionAddr *dst_addr`: Pointer to the [ScionAddr](/docs/structs/scion_addr.md) structure specifying the destination address. Must not be `NULL`. The address must be properly initialized, and its family must be either `AF_INET` (IPv4) or `AF_INET6` (IPv6).
- `ScionPath *path`: Pointer to the [ScionPath](/docs/structs/scion_path.md) structure specifying the path. If set to `NULL`, a path between the source and destination AS will automatically be build, by default the shortest. 

### Return values
The function returns an integer value indicating the result of the sendto operation:

- `>= 0`: Number of message bytes successfully sent.
- `< 0`: Error codes as specified in `error.h`

### Notes
- This is a wrapper around the standard POSIX `sendto` function, tailored for SCION socket abstractions and to to send SCION packets.

### Usage example

### See also
- Structs:
[ScionSocket](/docs/structs/scion_socket.md), [ScionAddr](/docs/structs/scion_addr.md), [ScionPath](/docs/structs/scion_path.md)
- Functions: [scion_socket](/docs/functions/scion_socket.md), [scion_connect](/docs/functions/scion_connect.md), [scion_send](/docs/functions/scion_send.md), [scion_recv](/docs/functions/scion_recv.md), [scion_recvfrom](/docs/functions/scion_recvfrom.md), [scion_setsockopt](/docs/functions/scion_setsockopt.md), [scion_close](/docs/functions/scion_close.md), [scion_set_path](/docs/functions/scion_set_path.md)