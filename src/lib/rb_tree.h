
#ifndef _XL4BUS_LIB_RB_TREE_H_
#define _XL4BUS_LIB_RB_TREE_H_

#ifndef XI
#define XI(a) a
#endif

typedef struct rb_node {
    struct rb_node * left;
    struct rb_node * right;
    struct rb_node * parent;
    int is_red;
} rb_node_t;

typedef struct rb_tree_search {
    rb_node_t * node; // node that would receive next node
    rb_node_t ** link; // link through which the new item would be
                             // received
} rb_tree_search_t;

typedef struct rb_tree_nav {
    rb_node_t * node;
    rb_node_t * next;
} rb_tree_nav_t;

typedef int (*rb_tree_cmp_t)(rb_node_t *, void *);
typedef void (*rb_debug_hook_t)(char *, void *, void *);
typedef void (*rb_abort_hook_t)(const char *);

#define rb_tree_next XI(rb_tree_next)
#define rb_tree_start XI(rb_tree_start)
#define rb_find XI(rb_find)
#define rb_delete XI(rb_delete)
#define rb_insert XI(rb_insert)
#define rb_debug_hook XI(rb_debug_hook)
#define rb_abort_hook XI(rb_abort_hook)

extern void rb_tree_next(rb_tree_nav_t *);
extern rb_tree_nav_t * rb_tree_start(rb_tree_nav_t *, rb_node_t * root);
extern rb_node_t * rb_find(rb_node_t ** root, void * item, rb_tree_cmp_t , rb_tree_search_t*);
extern void rb_delete(rb_node_t ** root, rb_node_t * node);
extern void rb_insert(rb_node_t * node, rb_tree_search_t * placement, rb_node_t ** root);
extern rb_debug_hook_t rb_debug_hook;
extern rb_abort_hook_t rb_abort_hook;

#define SET_RB_NODE(val, addr) TO_NODE2(val, addr, rb_data)
#define SET_RB_NODE2(val, addr, elem) (val) = ((__typeof val)*)((void*)addr - ((void*)(&(val)->elem)-(void*)(val)))

#define TO_RB_NODE(type, addr) TO_RB_NODE2(type, addr, rb_data)
#define TO_RB_NODE2(type, addr, elem) ((type*)( ((void*)(addr)) - ( ((void*)(&((type*)(addr))->elem)) - ((void*)(addr)) )))
// #define TO_RB_NODE2(type, addr, elem) (((type)*) (addr - &addr->elem )

#endif
