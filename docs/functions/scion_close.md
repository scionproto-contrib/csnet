[Back to overview](/docs/main.md)

## scion_close
### Function signature:
```int scion_close(ScionSocket *scion_sock);```

### Description
The `scion_close` function closes a SCION socket, releasing its associated file descriptor and marking it as unavailable for further operations.

### Parameters
- `ScionSocket *scion_sock`: Pointer to the [ScionSocket](/docs/structs/scion_socket.md) structure representing the socket to close. This must not be `NULL`.

### Return values
The function returns an integer indicating the result of the operation:

- `0`: Success, the socket was closed successfully.
- `< 0`: Error codes as specified in `error.h`

### Notes
- `Error Propagation`: Any error encountered by the close call is returned to the caller.
- This is a wrapper around the standard POSIX `close` function, tailored for SCION socket abstractions.

### Usage example

### See also
- Structs:
[ScionSocket](/docs/structs/scion_socket.md), [ScionAddr](/docs/structs/scion_addr.md)
- Functions: [scion_socket](/docs/functions/scion_socket.md), [scion_connect](/docs/functions/scion_connect.md), [scion_send](/docs/functions/scion_send.md), [scion_sendto](/docs/functions/scion_sendto.md), [scion_recv](/docs/functions/scion_recv.md), [scion_recvfrom](/docs/functions/scion_recvfrom.md), [scion_setsockopt](/docs/functions/scion_setsockopt.md)