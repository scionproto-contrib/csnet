[Back to overview](/docs/main.md)

## scion_list_append
### Function signature:
```void scion_list_append(ScionLinkedList *list, void *value);```

### Description
Appends a new node containing a given value to the end of a [ScionLinkedList](/docs/structs/scion_linked_list.md). The function creates a new [ScionLinkedListNode](/docs/structs/scion_linked_list_node.md) to store the provided value, then appends this node to the end of the specified linked list. If the list is empty, the new node becomes both the first and last node. The function updates the list's size accordingly.

### Parameters
- `ScionLinkedList *list`: Pointer to the linked list where the new value should be appended.
- `void *value`: Pointer to the value to be stored in the new node. Can be any type of data.

### Return values
This function does not return a value.

### Notes
- If the input `list` is `NULL`, the function exits without performing any action.

### See also
- Structs: [ScionLinkedList](/docs/structs/scion_linked_list.md), [ScionLinkedListNode](/docs/structs/scion_linked_list_node.md)
- Functions: [scion_list_create](/docs/functions/scion_list_create.md), [scion_list_append_all](/docs/functions/scion_list_append_all.md), [scion_list_pop](/docs/functions/scion_list_pop.md), [scion_list_reverse](/docs/functions/scion_list_reverse.md), [scion_list_free_values](/docs/functions/scion_list_free_values.md), [scion_list_free](/docs/functions/scion_list_free.md)