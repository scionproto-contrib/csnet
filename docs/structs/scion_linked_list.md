[Back to overview](/docs/main.md)

## ScionLinkedList
### Definition
```
typedef struct ScionLinkedList {
	uint32_t size;
	ScionLinkedListNode *first;
	ScionLinkedListNode *last;
} ScionLinkedList;
```

### Description
Represents the base of a linked list, storing pointers to the first and last node in the list as well as the size of the list.

### Members
1. `uint32_t size`
    - Description: The number of nodes currently in the linked list.

2. `ScionLinkedListNode *first`
    - Description: A pointer to the first node in the linked list. If the list is empty, this pointer is `NULL`.

3. `ScionLinkedListNode *last`
    - Description: A pointer to the last node in the linked list. If the list is empty, this pointer is `NULL`.

### See also
- Structs: [ScionLinkedListNode](/docs/structs/scion_linked_list_node.md)
- Functions: [scion_list_create](/docs/functions/scion_list_create.md), [scion_list_append](/docs/functions/scion_list_append.md), [scion_list_append_all](/docs/functions/scion_list_append_all.md), [scion_list_pop](/docs/functions/scion_list_pop.md), [scion_list_reverse](/docs/functions/scion_list_reverse.md), [scion_list_free_values](/docs/functions/scion_list_free_values.md), [scion_list_free](/docs/functions/scion_list_free.md)