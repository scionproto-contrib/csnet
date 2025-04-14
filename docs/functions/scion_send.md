[Back to overview](/docs/main.md)

## scion_send
### Function signature:
```int scion_send(ScionSocket *scion_sock, const void *message, size_t length, int flags);```

### Description
The `scion_send` function sends a message through a SCION socket. It constructs a SCION packet, including headers and payload, serializes it, and sends it using a predefined SCION path. [scion_connect](/docs/functions/scion_connect.md) must have been called before being able to use `scion_send`, as it defines the destination and the path to use.

### Parameters
- `ScionSocket *scion_sock`: Pointer to a [ScionSocket](/docs/structs/scion_socket.md) structure. This represents the SCION socket to use for sending the message. Must not be `NULL` and must have a valid destination address, source address, and path.
- `const void *message`: Pointer to the message data to be sent. Can be `NULL` only if length is 0.
- `size_t length`: The length of the message in bytes. If length is greater than 0, message must not be `NULL`.
- `int flags`: Flags to pass to the underlying `send` call of the underlying POSIX socket.

### Return values
The function returns an integer value indicating the result of the send operation:

- `>= 0`: Number of message bytes successfully sent.
- `< 0`: Error codes as specified in `error.h`

### Notes
- Designed to behave like the POSIX `send` function, tailored for SCION socket abstractions and to to send SCION packets.

### Usage example

### See also
- Structs:
[ScionSocket](/docs/structs/scion_socket.md), [ScionAddr](/docs/structs/scion_addr.md)
- Functions: [scion_socket](/docs/functions/scion_socket.md), [scion_connect](/docs/functions/scion_connect.md), [scion_sendto](/docs/functions/scion_sendto.md), [scion_recv](/docs/functions/scion_recv.md), [scion_recvfrom](/docs/functions/scion_recvfrom.md), [scion_setsockopt](/docs/functions/scion_setsockopt.md), [scion_close](/docs/functions/scion_close.md), [scion_set_path](/docs/functions/scion_set_path.md)