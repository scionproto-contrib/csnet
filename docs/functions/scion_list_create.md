[Back to overview](/docs/main.md)

## scion_list_create
### Function signature:
```ScionLinkedList *scion_list_create(void);```

### Description
Allocates and initializes a new [ScionLinkedList](/docs/structs/scion_linked_list.md) structure, representing an empty linked list. Specifically, the size is set to 0, and the pointers to the first and last nodes are set to `NULL`.

### Parameters
No parameters


### Return values
The function returns:
- `NULL` if the memory allocation failed.
- Otherwise, a pointer (`ScionLinkedList *`) to the created [ScionLinkedList](/docs/structs/scion_linked_list.md) structure.

### Notes
- The [ScionLinkedList](/docs/structs/scion_linked_list.md) structure is allocated on the heap.

### See also
- Structs: [ScionLinkedList](/docs/structs/scion_linked_list.md), [ScionLinkedListNode](/docs/structs/scion_linked_list_node.md)
- Functions: [scion_list_append](/docs/functions/scion_list_append.md), [scion_list_append_all](/docs/functions/scion_list_append_all.md), [scion_list_pop](/docs/functions/scion_list_pop.md), [scion_list_reverse](/docs/functions/scion_list_reverse.md), [scion_list_free_values](/docs/functions/scion_list_free_values.md), [scion_list_free](/docs/functions/scion_list_free.md)
