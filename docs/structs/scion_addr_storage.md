[Back to overview](/docs/main.md)

## ScionAddrStorage
### Definition
```
typedef struct ScionAddrStorage {
    // Buffer storing the raw IP address
	uint8_t ip[16];

    // Length of the IP address
	uint8_t ip_len;

    // Port (if applicable)
	uint16_t port;

    // SCION ISD-AS number 
	ScionIA ia;

    // Path used by the sender
	ScionPath *path;
} ScionAddrStorage;
```

### Description
The `ScionAddrStorage` structure is used to store and represent addressing information of the source of a received SCION packet. It provides a generalized, flexible container for SCION addresses, including IP address data, port number, ISD-AS number and SCION path information. It it intended to be used with [scion_recvfrom](/docs/functions/scion_recvfrom.md).

### Members
1. `uint8_t ip[16]`
    - Description: Stores the IP address (IPv4 or IPv6) associated with the SCION address. Uses a 16-byte array to support both IPv4 (4 bytes) and IPv6 (16 bytes).

2. `uint8_t ip_len`
    - Description: Indicates the length of the IP address stored in the `ip` buffer.
    - Values:
        - `4` for IPv4
        - `16` for IPv6

3. `uint16_t port`
    - Description: Represents the transport-layer port associated with the SCION address, if applicable.
    - Notes:
        - If the transport-layer protocol (like SCMP) does not use ports, the value will be set to `0`.

4. `ScionIA ia`
    - Description: Represents the ISD-AS number of the AS in which the end host, which is represented by this address, is located.

5. `ScionPath *path`
    - Description: A pointer to a `ScionPath` structure, representing the SCION path used by the packet.
    - Notes:
        - Important: Needs to be reversed first using `scion_reverse_raw_path` before it can be used to send a response!
        - Should be used to respond to the received packet. In this case the response packet will use the same path as the original packet.

### See also
- Types: [ScionIA](/docs/types.md#scionia)
- Structs: [ScionSocket](/docs/structs/scion_socket.md), [ScionPath](/docs/structs/scion_path.md), [ScionAddr](/docs/structs/scion_addr.md)
- Functions: [scion_recvfrom](/docs/functions/scion_recvfrom.md)