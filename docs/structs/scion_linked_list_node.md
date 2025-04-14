[Back to overview](/docs/main.md)

## ScionLinkedListNode
### Definition
```
typedef struct ScionLinkedListNode ScionLinkedListNode;
struct ScionLinkedListNode {
	void *value;
	ScionLinkedListNode *next;
};
```

### Description
Represents a single node in a linked list, storing a pointer to a data value and a pointer to the next node in the list.

### Members
1. `void *value`
    - Description: A generic pointer to the value stored in the node. This can point to any data type, making the linked list structure highly flexible.

2. `ScionLinkedListNode *next`
    - Description: A pointer to the next node in the linked list. If this is the last node, the pointer is `NULL`.

### See also
- Structs: [ScionLinkedList](/docs/structs/scion_linked_list.md)
- Functions: [scion_list_create](/docs/functions/scion_list_create.md), [scion_list_append](/docs/functions/scion_list_append.md), [scion_list_append_all](/docs/functions/scion_list_append_all.md), [scion_list_pop](/docs/functions/scion_list_pop.md), [scion_list_reverse](/docs/functions/scion_list_reverse.md), [scion_list_free_values](/docs/functions/scion_list_free_values.md), [scion_list_free](/docs/functions/scion_list_free.md)