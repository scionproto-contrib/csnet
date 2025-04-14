[Back to overview](/docs/main.md)

## scion_list_free
### Function signature:
```void scion_list_free(ScionLinkedList *list);```

### Description
The `scion_list_free` function frees the memory allocated for a [ScionLinkedList](/docs/structs/scion_linked_list.md), including its nodes and the list structure itself. This function completely deallocates the list itself, but `does not` deallocate the values stored in the list.

### Parameters
- `ScionLinkedList *list`: Pointer to the linked list to be freed. If `NULL`, the function does nothing.

### Return values
This function does not return a value.

### Notes
`IMPORTANT`: Does not free the values in the nodes of the list. These need to be free'd (or accounted for) prior to calling `scion_list_free`.

### See also
- Structs: [ScionLinkedList](/docs/structs/scion_linked_list.md), [ScionLinkedListNode](/docs/structs/scion_linked_list_node.md)
- Functions: [scion_list_create](/docs/functions/scion_list_create.md), [scion_list_append](/docs/functions/scion_list_append.md), [scion_list_append_all](/docs/functions/scion_list_append_all.md), [scion_list_pop](/docs/functions/scion_list_pop.md), [scion_list_reverse](/docs/functions/scion_list_reverse.md), [scion_list_free_values](/docs/functions/scion_list_free_values.md)