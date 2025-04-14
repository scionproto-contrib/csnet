[Back to overview](/docs/main.md)

## scion_set_path
### Function signature:
```int scion_set_path(ScionSocket *scion_sock, ScionPath *path);```

### Description
Configures a SCION socket to use a specified SCION path for communication.

### Parameters
- `ScionSocket *scion_sock`: Pointer to a [ScionSocket](/docs/structs/scion_socket.md).
    - Note: Should have been previously initialized using [scion_socket](/docs/functions/scion_socket.md).

- `ScionPath *path`: Pointer to the [ScionPath](/docs/structs/scion_path.md) struct which will be set on the SCION socket.


### Return values
The function returns an integer indicating the result of the operation:

- `0`: Success, the socket was closed successfully.
- `< 0`: Error codes as specified in `error.h`

### Notes

### Usage example

### See also
- Structs: [ScionSocket](/docs/structs/scion_socket.md), [ScionPath](/docs/structs/scion_path.md)
- Functions: [scion_socket](/docs/functions/scion_socket.md), [scion_connect](/docs/functions/scion_connect.md), [scion_fetch_paths](/docs/functions/scion_fetch_paths.md), [scion_send](/docs/functions/scion_send.md)