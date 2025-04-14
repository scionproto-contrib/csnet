[Back to overview](/docs/main.md)

## scion_setsockopt
### Function signature:
```int scion_setsockopt(ScionSocket *scion_sock, int level, int option_name, const void *option_value, socklen_t option_len)```

### Description
The `scion_setsockopt` function configures options on a SCION socket by setting socket options of the underlying POSIX socket.

### Parameters
- `ScionSocket *scion_sock`: Pointer to the [ScionSocket](/docs/structs/scion_socket.md) structure for which the options are to be set. This must not be `NULL`.
- `int level`: The protocol level at which the option resides (e.g., SOL_SOCKET for general socket options).
- `int option_name`: The name of the option to set (like SO_RCVBUF etc.).
- `const void *option_value`: A pointer to the value for the specified option. The type and size of this value depend on the option being set.
- `socklen_t option_len`: The size, in bytes, of the buffer pointed to by option_value.

### Return values
The function returns an integer indicating the result of the operation:
- `0`: Success; the socket option was set successfully.
- `< 0`: Error codes as specified in `error.h` or errors returned by the underlying setsockopt call.

### Notes
- `Option Validation`: The function does not validate the level, option_name, or option_value parameters. It relies on the underlying `setsockopt` call to validate them.
- This is a wrapper around the standard POSIX `setsockopt` function, tailored for SCION socket abstractions.

### Usage example

### See also
- Structs:
[ScionSocket](/docs/structs/scion_socket.md)
- Functions: [scion_socket](/docs/functions/scion_socket.md), [scion_connect](/docs/functions/scion_connect.md), [scion_send](/docs/functions/scion_send.md), [scion_sendto](/docs/functions/scion_sendto.md), [scion_recv](/docs/functions/scion_recv.md), [scion_recvfrom](/docs/functions/scion_recvfrom.md), [scion_close](/docs/functions/scion_close.md)