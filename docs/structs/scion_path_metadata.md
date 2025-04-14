[Back to overview](/docs/main.md)

## ScionPathMetadata
### Definition
```
typedef struct ScionPathMetadata {
	uint16_t mtu;
	ScionLinkedList *interfaces;
} ScionPathMetadata;
```

### Description
The `ScionPathMetadata` structure provides additional information about a SCION path, such as the maximum transmission unit (MTU) and the sequence of interfaces used in the path.

### Members
1. `uint16_t mtu`
    - Description: Represents the Maximum Transmission Unit (MTU) for the SCION path (in bytes).

2. `ScionLinkedList *interfaces`
    - Description: Pointer to a linked list containing the sequence of [ScionPathInterface](/docs/structs/scion_path_interface.md) structures representing the interfaces in the path.
    - Notes:
        - Requires significantly more memory to store than the rest of the path. For memory constraint applications, storing the interfaces can be turned off during path creation. If turned off, `interfaces` will be `NULL`.
        - Required to pretty-print paths.

### See also
- Structs: [ScionLinkedList](/docs/structs/scion_linked_list.md), [ScionPathInterface](/docs/structs/scion_path_interface.md), [ScionPath](/docs/structs/scion_path.md)