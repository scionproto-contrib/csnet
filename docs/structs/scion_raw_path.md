[Back to overview](/docs/main.md)

## ScionRawPath
### Definition
```
typedef struct ScionRawPath {
    // Length of the raw buffer
	uint16_t length;

    // Pointer to the buffer containing the serialized path
	uint8_t *raw;
} ScionRawPath;
```

### Description
The `ScionRawPath` structure represents the raw binary representation of a SCION path.

### Members
1. `uint16_t length`
    - Description: Specifies the length of the raw path data in bytes.

2. `uint8_t *raw`
    - Description: Pointer to a buffer containing the raw binary data of the SCION path.

### See also
- Structs: [ScionPath](/docs/structs/scion_path.md)
- Functions: [scion_fetch_paths](/docs/functions/scion_fetch_paths.md)