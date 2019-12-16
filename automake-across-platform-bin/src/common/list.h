#ifndef _LLIST_H
#define _LLIST_H


struct list_head {
	struct list_head *next;
	struct list_head *prev;
};

/**
 * initiate the list
 */
#define INIT_LIST_HEAD(head) do {			\
		(head)->next = (head)->prev = head;	\
	} while (0)


/**
 * add new list_head into one list at the beginning
 * (generally speaking, the first element in one list doesn't contain an structure, i.e. simple list_head object)
 */
static inline void list_add (struct list_head *_new, struct list_head *head)
{
	_new->prev = head;
	_new->next = head->next;

	_new->prev->next = _new;
	_new->next->prev = _new;
}

/**
 * add _new list_head into one list at the ending
 * (generally speaking, the first element in one list doesn't contain an structure, i.e. simple list_head object)
 */
static inline void list_add_tail (struct list_head *_new, struct list_head *head)
{
	_new->next = head;
	_new->prev = head->prev;

	_new->prev->next = _new;
	_new->next->prev = _new;
}

/**
 * delete an list_head from the list containing it
 */
static inline void list_del (struct list_head *old)
{
	old->prev->next = old->next;
	old->next->prev = old->prev;

    old->next = (struct list_head *)0xbbbbbbbb;
    old->prev = (struct list_head *)0xcccccccc;
}

/**
 * delete an list_head from the list containing it
 * and initite itself
 */
static inline void list_del_init (struct list_head *old)
{
	old->prev->next = old->next;
	old->next->prev = old->prev;

	old->next = old;
	old->prev = old;
}

/**
 * check if the list is empty
 * (generally speaking, the first element in one list doesn't contain an structure, i.e. simple list_head object
 */
static inline int list_empty (struct list_head *head)
{
	return (head->next == head);
}

static inline int list_size(struct list_head *head){
	struct list_head* find;
	int num;

	num = 0;
	find = head->next;
	while(find != head){
		num ++;
		find = find->next;
	}

	return num;
}

/**
 * from the structure member to the the structure
 * eg:
 * struct exa_struct{
 * 		int a;
 * 		list_head here_pos;
 * 		...;
 * }
 *
 * list_head *my_head = ...; //which is contained in the exa_sturct structure
 *
 * //you can get the exa_structure pointer by
 * exa_struct *p = list_entry(my_head, struct exa_struct, here_pos);
 *
 */
#define list_entry(ptr, type, member)					\
	((type *)((char *)(ptr)-(unsigned long)(&((type *)0)->member)))

/**
 * traverse the whole list. Notice, the first one list_head not containing 
 * the structure, which only stands for an list_head object
 *
 * you can use like this:
 *
 * list_head* head;
 * ...
 * ...
 *
 * list_head* trav_head;
 * list_for_each(trav_head, head){
 * 	....
 * 	....
 * 	....
 * }
 */
#define list_for_each(pos, head)				     \
	for (pos = (head)->next; pos != (head); pos = pos->next)

/**
 * pos: structure pointer
 * head: list header
 * member: name of list_head in the structure
 */
#define list_for_each_entry(pos, head, member)				\
	for (pos = list_entry((head)->next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = list_entry(pos->member.next, typeof(*pos), member))

/**
 * pos: structure pointer, used in the loop body
 * n: structure pointer, not used in the loop body
 * head: list header
 * member: name of list_head in the structure
 */
 
#define list_for_each_entry_safe(pos, n, head, member)			\
	for (pos = list_entry((head)->next, typeof(*pos), member),	\
		n = list_entry(pos->member.next, typeof(*pos), member);	\
	     &pos->member != (head); 					\
	     pos = n, n = list_entry(n->member.next, typeof(*n), member))

#endif /* _LLIST_H */
