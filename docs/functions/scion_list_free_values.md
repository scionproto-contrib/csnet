[Back to overview](/docs/main.md)

## scion_list_free_values
### Function signature:
```void scion_list_free_values(ScionLinkedList *list);```

### Description
The `scion_list_free_values` function frees the memory allocated for the values stored in each node of a [ScionLinkedList](/docs/structs/scion_linked_list.md) without deallocating the list itself or its nodes. It iterates over all the nodes of a [ScionLinkedList](/docs/structs/scion_linked_list.md) and frees the memory associated with their `value` pointers. The `value` pointers in each node are then set to `NULL` to prevent dangling references. The list structure, including its nodes and links, remains intact.

### Parameters
- `ScionLinkedList *list`: Pointer to the linked list whose node values will be freed. If `NULL`, the function does nothing.

### Return values
This function does not return a value.

### Notes
`IMPORTANT`: Should only be used if every value in the list can be free'd using a simple `free` function call. Should `NOT` be used if the list contains values that cannot be free'd (for example, due to allocation on the stack) or if the values represent more complicated structs that required specialized functions to be free'd correctly. This could otherwise lead to unsafe usage of `free` or memory leaks.

### See also
- Structs: [ScionLinkedList](/docs/structs/scion_linked_list.md), [ScionLinkedListNode](/docs/structs/scion_linked_list_node.md)
- Functions: [scion_list_create](/docs/functions/scion_list_create.md), [scion_list_append](/docs/functions/scion_list_append.md), [scion_list_append_all](/docs/functions/scion_list_append_all.md), [scion_list_pop](/docs/functions/scion_list_pop.md), [scion_list_reverse](/docs/functions/scion_list_reverse.md), [scion_list_free](/docs/functions/scion_list_free.md)