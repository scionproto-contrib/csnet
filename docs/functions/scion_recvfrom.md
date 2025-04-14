[Back to overview](/docs/main.md)

## scion_recvfrom
### Function signature:
```int scion_recvfrom(ScionSocket *scion_sock, void *buf, size_t len, int flags, ScionAddrStorage *saddr);```

### Description
The `scion_recvfrom` function receives a message from a SCION socket and captures information about the sender's address. It deserializes the received SCION packet, processes its payload, and stores the result in the provided buffer. The function supports handling SCION UDP and SCION Control Message Protocol (SCMP) packets.

### Parameters
- `ScionSocket *scion_sock`: Pointer to a [ScionSocket](/docs/structs/scion_socket.md) structure. This is the SCION socket from which the data will be received. Must not be `NULL`.
- `void *buf`: Pointer to a buffer where the received data will be stored. Must not be `NULL`.
- `size_t len`: The size of the buffer in bytes. Determines the maximum amount of data that can be stored in buf.
- `int flags`: Flags to pass to the underlying `recv` call of the underlying POSIX socket.
- `ScionAddrStorage *saddr`: Pointer to a [ScionAddrStorage](/docs/structs/scion_addr_storage.md) structure where the sender's address information will be stored, including SCION-specific fields like ISD-AS and path. Must not be `NULL`.

### Return values
The function returns an integer indicating the result of the recvfrom operation:

- `>= 0`: Number of bytes successfully received and stored in `buf`.
- `< 0`: Error codes as specified in `error.h`

### Notes
- `SCION UDP Handling`: The UDP header is stripped from the payload before copying it to buf. This means the application only receives the raw UDP payload.
- `SCMP Handling`: When an SCMP message is received, the function copies the payload up to the buffer size and sets the `scmp_alert` flag to true.
- `Buffer Size`:
Ensure len is sufficiently large to accommodate expected data. If len is smaller than the payload size, only the first len bytes are copied.
- This is a wrapper around the standard POSIX `recvfrom` function, tailored for SCION socket abstractions and to receive SCION packets.

### Usage example

### See also
- Structs:
[ScionSocket](/docs/structs/scion_socket.md), [ScionAddr](/docs/structs/scion_addr.md), [ScionAddrStorage](/docs/structs/scion_addr_storage.md)
- Functions: [scion_socket](/docs/functions/scion_socket.md), [scion_connect](/docs/functions/scion_connect.md), [scion_send](/docs/functions/scion_send.md), [scion_sendto](/docs/functions/scion_sendto.md), [scion_recv](/docs/functions/scion_recv.md), [scion_setsockopt](/docs/functions/scion_setsockopt.md), [scion_close](/docs/functions/scion_close.md)