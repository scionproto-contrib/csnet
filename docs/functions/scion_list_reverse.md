[Back to overview](/docs/main.md)

## scion_list_reverse
### Function signature:
```void scion_list_reverse(ScionLinkedList *list);```

### Description
The `scion_list_reverse` function reverses the order of nodes in a [ScionLinkedList](/docs/structs/scion_linked_list.md). After execution, the first node becomes the last, and the last node becomes the first. The function modifies the `first` and `last` pointers of the list to reflect the new order.

### Parameters
- `ScionLinkedList *list`: Pointer to the linked list to be reversed. Must not be `NULL`.

### Return values
This function does not return a value.

### See also
- Structs: [ScionLinkedList](/docs/structs/scion_linked_list.md), [ScionLinkedListNode](/docs/structs/scion_linked_list_node.md)
- Functions: [scion_list_create](/docs/functions/scion_list_create.md), [scion_list_append](/docs/functions/scion_list_append.md), [scion_list_append_all](/docs/functions/scion_list_append_all.md), [scion_list_pop](/docs/functions/scion_list_pop.md), [scion_list_free_values](/docs/functions/scion_list_free_values.md), [scion_list_free](/docs/functions/scion_list_free.md)