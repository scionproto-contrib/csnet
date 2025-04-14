[Back to overview](/docs/main.md)

## ScionTopology
### Definition
```
typedef struct ScionTopology {
    // ISD-AS number of the local AS
    ScionIA ia;

    // Boolean indicating if the local AS is a core AS
	bool local_core;

    // Pointer to a String containing the Control Server IP
	char *cs_ip;

    // Port of the Control Server
	uint16_t cs_port;

    // Address family used by the border routers
	int local_addr_family;

    // Linked list containing the border router information
	ScionLinkedList *border_routers;
} ScionTopology;
```

### Description
The `ScionTopology` structure represents the topology information for a local AS (Autonomous System). It contains information about the local AS's role (core or non-core), the Control Service (CS) endpoint, the address family, and its border routers.


### Members
1. `ScionIA ia`
    - Description: ISD-AS number of the local AS.

1. `bool local_core`
    - Description: Indicates whether the local AS is part of the core of its ISD.
    - Values:
        - `true`: Core AS.
        - `false`: Non-core AS.

1. `char *cs_ip`
    - Description: Pointer to a string containing the IP address of a SCION Control Server of the local AS.

1. `uint16_t cs_port`
    - Description: The port number used to communicate with the SCION Control Server.

1. `int local_addr_family`
    - Description: Specifies the address family of the border routers of local AS.
    - Values:
        - `AF_INET`: for IPv4
        - `AF_INET6`: for IPv6

1. `ScionLinkedList *border_routers`
    - Description: Linked list of border routers of the AS.
    - Notes:
        - Each value in the list is a pointer to a [ScionBorderRouter](/docs/structs/scion_border_router.md) struct.


### See also
- Types: [ScionIA](/docs/types.md#scionia)
- Structs: [ScionLinkedList](/docs/structs/scion_linked_list.md), [ScionBorderRouter](/docs/structs/scion_border_router.md)
- Functions: [scion_socket](/docs/functions/scion_socket.md)