[Back to overview](/docs/main.md)

## ScionBorderRouter
### Definition
```
typedef struct ScionBorderRouter {
    // Interface ID 
	uint16_t ifid;

    // Pointer to a string containing the border router IP
	char *ip;

    // Port of the given interface
	uint16_t port;
} ScionBorderRouter;
```

### Description
The `ScionBorderRouter` represents a border router in a SCION AS. Border routers serve as gateways to connect the local AS to other ASes.


### Members
1. `uint16_t ifid`
    - Description: Interface identifier (IFID) associated with the border router. Uniquely identifies the connection point of the router within the AS.

1. `char *ip`
    - Description: Pointer to a string containing the IP address of the border router.

1. `uint16_t port`
    - Description: The port number used for communication with the border router (and the given interface).


### See also
- Structs: [ScionSocket](/docs/structs/scion_socket.md), [ScionTopology](/docs/structs/scion_topology.md)