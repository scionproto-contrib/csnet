[Back to overview](/docs/main.md)

## scion_fetch_paths
### Function signature:
```int scion_fetch_paths(ScionTopology *t, ScionIA src, ScionIA dst, ScionLinkedList *paths, int opt);```

### Description
The `scion_fetch_paths` function fetches path segments and constructs SCION paths between a source and a destination ISD-AS using a SCION Control Server. The function appends the constructed paths to the provided linked list.

### Parameters
- `ScionTopology *t`: Pointer to a [ScionTopology](/docs/structs/scion_topology.md) structure containing the topology information of the local AS. This must not be `NULL`.
- `ScionIA src`: The source ISD-AS identifier.
- `ScionIA dst`: The destination ISD-AS identifier.
- `ScionLinkedList *paths`: Pointer to a linked list where the function appends the constructed paths.
- `int opt`: Options for path construction.
    - Values: 
        - `SCION_PATH_DEBUG (1)`: The `interfaces` list of the [ScionPathMetadata](/docs/structs/scion_path_metadata.md) of a constructed path is populated to keep a list of ASes through which the path goes. Enables pretty-printing of the path, as well as path selection based on ASes. Requires more memory.
        - `0`: The `interfaces` list of the [ScionPathMetadata](/docs/structs/scion_path_metadata.md) is not populated.


### Return values
The function returns an integer indicating the result of the operation:

- `0`: Success, the socket was closed successfully.
- `< 0`: Error codes as specified in `error.h`

### Notes

### Usage example

### See also
- Types: [ScionIA](/docs/types.md#scionia)
- Structs:
[ScionSocket](/docs/structs/scion_socket.md), [ScionTopology](/docs/structs/scion_topology.md), [ScionPath](/docs/structs/scion_path.md), [ScionLinkedList](/docs/structs/scion_linked_list.md), [ScionPathMetadata](/docs/structs/scion_path_metadata.md)
- Functions: [scion_set_path](/docs/functions/scion_set_path.md)