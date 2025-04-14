[Back to overview](/docs/main.md)

## scion_list_append_all
### Function signature:
```void scion_list_append_all(ScionLinkedList *dst_list, ScionLinkedList *src_list);```

### Description
The `scion_list_append_all` function appends all elements from one [ScionLinkedList](/docs/structs/scion_linked_list.md) to another. It iterates through all nodes in the source linked list and appends each node's value to the destination linked list. The source list remains unchanged.

### Parameters
- `ScionLinkedList *dst_list`: Pointer to the destination linked list where the values from the source list will be appended. Must not be `NULL`.
- `ScionLinkedList *src_list`: Pointer to the source linked list whose values will be appended to the destination list. Must not be `NULL`.

### Return values
This function does not return a value.

### Notes
- If either `dst_list` or `src_list` is `NULL`, the function performs no action and returns immediately.
- The source list is not modified by this function. Its nodes and structure remain intact.

### See also
- Structs: [ScionLinkedList](/docs/structs/scion_linked_list.md), [ScionLinkedListNode](/docs/structs/scion_linked_list_node.md)
- Functions: [scion_list_create](/docs/functions/scion_list_create.md), [scion_list_append](/docs/functions/scion_list_append.md), [scion_list_pop](/docs/functions/scion_list_pop.md), [scion_list_reverse](/docs/functions/scion_list_reverse.md), [scion_list_free_values](/docs/functions/scion_list_free_values.md), [scion_list_free](/docs/functions/scion_list_free.md)