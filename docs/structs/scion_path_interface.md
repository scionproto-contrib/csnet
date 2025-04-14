[Back to overview](/docs/main.md)

## ScionPathInterface
### Definition
```
typedef struct ScionPathInterface {
    // ID of the interface
	uint16_t id;

    // ISD-AS number of the AS in which the interface is located
	ScionIA ia;
} ScionPathInterface;
```

### Description
The `ScionPathInterface` structure represents an interface in a SCION network path. Each interface uniquely identifies a connection point between two autonomous systems (ASes) within the SCION Internet Architecture.

### Members
1. `uint16_t id`
    - Description: Represents the interface identifier (IFID).

2. `ScionIA ia`
    - Description: ISD-AS number of the AS in which the interface is located.

### See also
- Types: [ScionIA](/docs/types.md#scionia)
- Structs: [ScionPathMetadata](/docs/structs/scion_path_metadata.md)