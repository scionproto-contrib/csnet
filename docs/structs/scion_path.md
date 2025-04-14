[Back to overview](/docs/main.md)

## ScionPath
### Definition
```
typedef struct ScionPath {
    // Destination AS of the path
	ScionIA dst;

    // Interface ID of the first hop
	uint16_t first_hop_ifid;

    // Path type
	uint8_t path_type;

    // Raw (i.e. serialized) path
	ScionRawPath *raw_path;

    // Path metadata
	ScionPathMetadata *metadata;

    // Weight (i.e. length) of the path
	uint32_t weight;
} ScionPath;
```

### Description
The `ScionPath` structure is used to encapsulate detailed information about a SCION path. SCION paths describe the route taken by packets through a SCION network.

### Members
1. `ScionIA dst`
    - Description: ISD-AS number of the destination to which this path leads.

2. `uint16_t first_hop_ifid`
    - Description: Represents the interface ID of the first hop in the path. This ID identifies the SCION router/interface where the path begins.

3. `uint8_t path_type`
    - Description: Indicates the type of SCION path.
    - Values:
        - `SCION_PATH_TYPE_EMPTY` for an empty path.
        - `SCION_PATH_TYPE_SCION` for a SCION path.

4. `ScionRawPath *raw_path`
    - Description: Pointer to a [ScionRawPath](/docs/structs/scion_raw_path.md) structure that contains the raw binary representation of the SCION path.

5. `ScionPathMetadata *metadata`
    - Description: Pointer to a [ScionPathMetadata](/docs/structs/scion_path_metadata.md) structure, which contains additional metadata (such as MTU) of the path.

6. `uint32_t weight`
    - Description: Represents the weight / length associated with this path.

### See also
- Types: [ScionIA](/docs/types.md#scionia)
- Structs: [ScionRawPath](/docs/structs/scion_raw_path.md), [ScionPathMetadata](/docs/structs/scion_path_metadata.md), [ScionSocket](/docs/structs/scion_socket.md)
- Functions: [scion_fetch_paths](/docs/functions/scion_fetch_paths.md), [scion_set_path](/docs/functions/scion_set_path.md)