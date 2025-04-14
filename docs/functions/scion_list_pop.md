[Back to overview](/docs/main.md)

## scion_list_pop
### Function signature:
```void *scion_list_pop(ScionLinkedList *list);```

### Description
Removes and returns the value stored in the first node of a [ScionLinkedList](/docs/structs/scion_linked_list.md). The members of the list are updated accordingly.

### Parameters
- `ScionLinkedList *list`: Pointer to the linked list from which the first node's value will be removed. Must not be `NULL`.

### Return values
- `void *`: Pointer to the value stored in the removed node. `NULL` if `list` is `NULL` or empty.

### See also
- Structs: [ScionLinkedList](/docs/structs/scion_linked_list.md), [ScionLinkedListNode](/docs/structs/scion_linked_list_node.md)
- Functions: [scion_list_create](/docs/functions/scion_list_create.md), [scion_list_append](/docs/functions/scion_list_append.md), [scion_list_append_all](/docs/functions/scion_list_append_all.md), [scion_list_reverse](/docs/functions/scion_list_reverse.md), [scion_list_free_values](/docs/functions/scion_list_free_values.md), [scion_list_free](/docs/functions/scion_list_free.md)