[Back to overview](/docs/main.md)

## scion_parse_ia
### Function signature:
```int scion_parse_ia(const char *buf, uint16_t len, ScionIA *ia)```

### Description
The `scion_parse_ia` function processes an ISD-AS string (e.g., `"1-ff00:0:110"`), validates and parses the ISD and AS components, and combines them into a `ScionIA` structure.


### Parameters
- `const char *buf`: Pointer to the buffer containing the ISD-AS string.

- `uint16_t len`: Length of the buffer containing the ISD-AS string.

- `ScionIA *ia`: Pointer to [ScionIA](/docs/types.md#scionia) variable into which the result will be stored.


### Return values
The function returns an integer indicating the result of the receive operation:

- `0`: Number of bytes successfully received and stored in `buf`.
- `< 0`: Error codes as specified in `error.h`

### See also
- Types: [ScionIA](/docs/types.md#scionia)
- Structs: [ScionAddr](/docs/structs/scion_addr.md)