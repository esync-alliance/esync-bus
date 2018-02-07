
#ifdef XL4BUS_BUILD
#include "porting.h"
#endif

#include "rb_tree.h"

rb_debug_hook_t rb_debug_hook = 0;
rb_abort_hook_t rb_abort_hook = 0;

static void rb_grand(rb_node_t*, rb_node_t**, rb_node_t**);

static void rb_update1(rb_node_t*, rb_node_t ** root);
static void rb_update2(rb_node_t*, rb_node_t ** root);
static void rb_update3(rb_node_t*, rb_node_t ** root);
static void rb_update4(rb_node_t*, rb_node_t ** root);
static void rb_update5(rb_node_t*, rb_node_t ** root);
static void rb_rotate_left(rb_node_t*, rb_node_t ** root);
static void rb_rotate_right(rb_node_t*, rb_node_t ** root);
static void rb_exchange(rb_node_t*, rb_node_t*, rb_node_t***);
static void rb_delete1(rb_node_t*, rb_node_t ** root);
static void rb_delete2(rb_node_t*, rb_node_t ** root);
static void rb_delete3(rb_node_t*, rb_node_t ** root);
static void rb_delete4(rb_node_t*, rb_node_t ** root);
static void rb_delete5(rb_node_t*, rb_node_t ** root);
static void rb_delete6(rb_node_t*, rb_node_t ** root);
static rb_node_t * rb_sibling(rb_node_t*);
static rb_node_t * rb_next_node(rb_node_t *);

#ifdef TEST_AFTER
static void _rb_insert(void * node, rbtree_search_t * storage, void * root);
static void _rb_delete(rb_node_t ** root, rb_node_t * node);
static void test_tree(rb_node_t * root);
#endif

rb_node_t * rb_find(rb_node_t ** root, void * item, rb_tree_cmp_t cmp_f, rb_tree_search_t * storage) {

    rb_node_t * node;

    storage->link = root;
    node = storage->node = *storage->link;

    if (!node) { return 0; }

    while (1) {

        int cmp_r = cmp_f(storage->node, item);

        if (!cmp_r) { return node; }

        if (cmp_r < 0) {
            storage->link = &(node->right);
        } else {
            storage->link = &(node->left);
        }

        node = *storage->link;

        if (node) {
            storage->node = node;
        } else {
            break;
        }
    }
    return 0;
}

void rb_insert(rb_node_t * node, rb_tree_search_t * storage, rb_node_t ** root) {

#ifdef TEST_AFTER

    _rb_insert(node, storage, root);

    test_tree(*(rb_node_t**)root);

}

void _rb_insert(void * node, rbtree_search_t * storage, void * root) {

#endif

    rb_node_t * current;
    node->left = 0;
    node->right = 0;

    // Note, that any added node is always added as a leaf,
    // no exceptions. The special case is when we are adding
    // the first node, which is always root.

    if (!storage->node) {
        // the new node is root
        // make it black, and we are done.
        *storage->link = node;
        node->parent = 0;
        node->is_red = 0;
        return;
    }

    *storage->link = node;
    node->parent = storage->node;

    // it's guaranteed that the inserted node
    // has a parent, because we have processed
    // the special case of root above.

    current = node;

    // when a node is inserted it's given color red.
    current->is_red = 1;

    while (1) {

        rb_node_t * parent = current->parent;
        rb_node_t * grand;
        rb_node_t * uncle;
        int current_is_left;
        int redo = 0;

        if (!parent) {
            // we ran all the way up to root.
            // paint it black, and exit
            current->is_red = 0;
            break;
        }

        // if the parent is black, there is no
        // problem anymore (even if we are moving up)
        if (!parent->is_red) {
            break;
        }

        // because parent is red, grandparent must
        // exist, so we never check.

        rb_grand(current, &grand, &uncle);
        // parent is red already, we know that
        // if uncle also is red, we'll repaint a bit
        if (uncle && uncle->is_red) {
            parent->is_red = 0;
            uncle->is_red = 0;
            grand->is_red = 1;
            current = grand;
            continue;
        }

        current_is_left = current == parent->left;

        if (!current_is_left &&
            parent == grand->left) {
            rb_rotate_left(parent, root);
            current_is_left = 1;
            current = current->left;
            redo = 1;
        } else if (current_is_left &&
                   parent == grand->right) {
            rb_rotate_right(parent, root);
            current_is_left = 0;
            current = current->right;
            redo = 1;
        }

        if (redo) {
            parent = current->parent;
            rb_grand(current, &grand, &uncle);
        }

        parent->is_red = 0;
        grand->is_red = 1;
        if (current_is_left) {
            rb_rotate_right(grand, root);
        } else {
            rb_rotate_left(grand, root);
        }

    }

}

void rb_update1(rb_node_t * n, rb_node_t ** root) {

    if (!n->parent) {
        n->is_red = 0;
    } else {
        rb_update2(n, root);
    }

}

void rb_update2(rb_node_t * n, rb_node_t ** root) {

    if (n->parent->is_red) {
        rb_update3(n, root);
    } else {
        return;
    }

}

void rb_update3(rb_node_t * n, rb_node_t ** root) {

    rb_node_t * grand;
    rb_node_t * uncle;

    rb_grand(n, &grand, &uncle);

    if (uncle && uncle->is_red) {
        n->parent->is_red = 0;
        uncle->is_red = 0;
        grand->is_red = 1;
        rb_update1(grand, root);
    } else {
        rb_update4(n, root);
    }

}

void rb_update4(rb_node_t * n, rb_node_t ** root) {

    rb_node_t * grand;

    rb_grand(n, &grand, 0);

    if ((n == n->parent->right) && grand && (n->parent == grand->left)) {
        rb_rotate_left(n->parent, root);
        n = n->left;
    } else if ((n == n->parent->left) && grand && (n->parent == grand->right)) {
        rb_rotate_right(n->parent, root);
        n = n->right;
    }
    rb_update5(n, root);
}

void rb_update5(rb_node_t * n, rb_node_t ** root) {

    rb_node_t * grand;

    rb_grand(n, &grand, 0);

    n->parent->is_red = 0;
    if (!grand)
        return;

    grand->is_red = 1;

    if (n == n->parent->left) {
        rb_rotate_right(grand, root);
    } else {
        rb_rotate_left(grand, root);
    }
}

// The assumption is that we are always using predecessor (max element
// in the left sub-tree), so the 'onelink' node will always have it's
// child (if any) on the left, and the right leaf is always nil. It also
// means that oneleaf is guaranteed to be a right node of it's parent.
//
// If both twoleaf and oneleaf are in direct relationship, the oneleaf
// is guaranteed to be on left side of twoleaf.
//
// parent_link points to the parent of the twoleaf.
void rb_exchange(rb_node_t * twoleaf, rb_node_t * oneleaf,
        rb_node_t *** parent_link) {

    rb_node_t * twos_parent = twoleaf->parent;
    rb_node_t ** new_parent_link;

    // no matter what, the colors must be exchanged.
    if (twoleaf->is_red != oneleaf->is_red) {
        int a = twoleaf->is_red;
        twoleaf->is_red = oneleaf->is_red;
        oneleaf->is_red = a;
    }

    if (twoleaf->left == oneleaf) {
        // direct descendant, special case

        rb_node_t * a = oneleaf->left; // can be 0
        rb_node_t * b = twoleaf->right; // not 0

        oneleaf->right = b;
        b->parent = oneleaf;

        oneleaf->left = twoleaf;
        twoleaf->parent = oneleaf;

        twoleaf->left = a;
        if (a) {
            a->parent = twoleaf;
        }
        new_parent_link = &oneleaf->left;

    } else {

        rb_node_t * a = twoleaf->left; // not 0
        rb_node_t * b = twoleaf->right; // not 0

        rb_node_t * c = oneleaf->parent; // not 0
        rb_node_t * d = oneleaf->left; // can be 0

        oneleaf->left = a;
        a->parent = oneleaf;

        oneleaf->right = b;
        b->parent = oneleaf;

        c->right = twoleaf;
        twoleaf->parent = c;

        twoleaf->left = d;
        if (d) {
            d->parent = twoleaf;
        }

        new_parent_link = &c->right;

    }

    twoleaf->right = 0;
    oneleaf->parent = twos_parent;
    if (*parent_link) {
        **parent_link = oneleaf;
    }
    *parent_link = new_parent_link;

}

void rb_grand(rb_node_t * node, rb_node_t ** grand, rb_node_t ** uncle) {

    node = node->parent;
    if (!node || !node->parent) {
        *grand = 0;
        if (uncle) { *uncle = 0; }
        return;
    } else {
        *grand = node->parent;
    }

    if (uncle) {
        if (node == (*grand)->left) {
            *uncle = (*grand)->right;
        } else {
            *uncle = (*grand)->left;
        }
    }

}

void rb_delete(rb_node_t ** root, rb_node_t * node) {

#ifdef TEST_AFTER

    _rb_delete(_root, _node);
    test_tree(*(rb_node_t**)_root);

}

void _rb_delete(rb_node_t ** root, rb_node_t * node) {

#endif

    rb_node_t ** parent_link;
    rb_node_t * replacement;

    int is_root = node == *root;

    if (is_root) {
        parent_link = 0;
    } else {
        if (node->parent->left == node) {
            parent_link = &node->parent->left;
        } else {
            parent_link = &node->parent->right;
        }
    }

    // most complicated case - both leaves present

    if (node->left && node->right) {

        // let me explain this.
        // Deleting a node with two leaf links is easier
        // if we replaced it first with next value over, and
        // then deleted that value instead. This is great for
        // binary trees, but doesn't that well work when elements
        // are pointers to memory we (this function) doesn't control.
        // So we can't just replace a value, and delete a different
        // element, we have to exchange the values around instead.
        //
        // The "next value over" is either right-most element on the
        // left side, or left-most element on the right side. Theoretically,
        // we should check which element will be easier to use, but we have
        // to have the logic to delete it in either case, so we just
        // always pick the one on the left side.

        replacement = node->left;

        while (replacement->right) {
            replacement = replacement->right;
        }

        rb_exchange(node, replacement, &parent_link);

        if (is_root) {
            *root = replacement;
            // replacement's parent should have been 0'ed already.
            // replacement->parent = 0;
            is_root = 0;
        }

        if (rb_debug_hook) {
            rb_debug_hook("r:2l<->1l", 0, *root);
        }
    }

    // at this point, node has at most one child
    // To "delete" a node, we need to now simply "replace"
    // it in the tree by its "replacement". replacement can be
    // very much nil, if the node being deleted has no children.

    replacement = node->left ? node->left : node->right;

    if (is_root) {
        *root = replacement;
        // if we deleted root, there is nothing else we need to do,
        // let's just null the parent of the new root, if any, and
        // make the new root black.
        if (replacement) {
            replacement->parent = 0;
            replacement->is_red = 0;
        }
        return;
    }

    if (!replacement) {

        if (node->is_red) {
            // if the node is red, we can just throw it out
            *parent_link = 0;
            node->parent = 0;
        } else {

            // there is no child below that we can replace this node with.
            // We'll process the node itself instead, and then snip this
            // node off.

            rb_delete1(node, root);

            // above could've changed tree structure, we need
            // to re-establish child relationship.

            if (node->parent->left == node) {
                node->parent->left = 0;
            } else {
                node->parent->right = 0;
            }

            node->parent = 0;

        }


        if (node->left || node->right) {
            // safety check.
            rb_abort_hook("deleting non-empty node");
        }

    } else {

        *parent_link = replacement;

        replacement->parent = node->parent;

        node->parent = 0;

        if (!node->is_red) {
            if (replacement->is_red) {
                replacement->is_red = 0;
            } else {
                rb_delete1(replacement, root);
            }
        }

    }

}

void rb_delete1(rb_node_t * n, rb_node_t ** root) {

    // this only is executed, when we are removing
    // a black node, and can only replace it with black node.
    // Both these black nodes are on the same path. 
    // Which means that the parallel path has to have
    // at least 2 levels of black nodes, may be with reds in between.
    // The reds, if any, will only lengthen the parallel branch.
    // Step#3 is the only step that recurses to parent, but the higher
    // up the tree we travel, only more guarantee of siblings is provided.
    //
    // One exception is when we rotate at step 2. But if we have
    // rotated at step 2, we will never even recurse, since n->parent
    // will be red (recursing is only if n->parent is black). Also, when
    // we rotate, we rotate only if sibling is red, which means that it
    // must have 2 black children.
    //
    // The only other exception is when a black node is removed without
    // a replacement. In which case, it's still guaranteed a sibling,
    // just not necessarily children of a sibling, but in that case the
    // sibling must be black (so no rotation at step 2). If such sibling
    // has no children, then we will either recurse at step 3, or exit at
    // step 4. If the sibling only has one child, the child must be red,
    // therefore the other child will be null, which we consider same as
    // black.

    while (1) {

        rb_node_t * parent = n->parent;
        rb_node_t * s;
        int black_sibling;

        if (!parent) { break; }

        s = rb_sibling(n);

        // step 2
        if (s->is_red) {

            parent->is_red = 1;
            s->is_red = 0;
            if (n == parent->left) {
                rb_rotate_left(parent, root);
            } else {
                rb_rotate_right(parent, root);
            }

            parent = n->parent;
            s = rb_sibling(n);
        }

        black_sibling = !s->is_red &&
                        (!s->left || !s->left->is_red ) &&
                        (!s->right || !s->right->is_red);

        // case 3 test
        if (black_sibling && !parent->is_red) {
            s->is_red = 1;
            n = parent;
            continue;
        }

        // case 4 test
        if (black_sibling && parent->is_red) {
            s->is_red = 1;
            parent->is_red = 0;
            break;
        }

        // case 5
        if (n == parent->left && (!s->right || !s->right->is_red)) {
            s->is_red = 1;
            s->left->is_red = 0;
            rb_rotate_right(s, root);

            s = rb_sibling(n);
            parent = n->parent;

        } else if (n == n->parent->right && (!s->left || !s->left->is_red)) {
            s->is_red = 1;
            s->right->is_red = 0;
            rb_rotate_left(s, root);

            s = rb_sibling(n);
            parent = n->parent;
        }

        s->is_red = parent->is_red;
        parent->is_red = 0;

        if (n == parent->left) {
            s->right->is_red = 0;
            rb_rotate_left(parent, root);
        } else {
            s->left->is_red = 0;
            rb_rotate_right(parent, root);
        }

        break;
    }

    /*
    if (n->parent) {
        rb_delete2(n, root);
    }
    */

}

void rb_delete2(rb_node_t * n, rb_node_t ** root) {

    rb_node_t * s = rb_sibling(n);

    // if s==0 then it's as if it was black.
    if (s && s->is_red) {
        n->parent->is_red = 1;
        if (rb_debug_hook) {
            rb_debug_hook("d2:red(n.p)", n, *root);
        }
        s->is_red = 0;
        if (rb_debug_hook) {
            rb_debug_hook("d2:blk(s)", s, *root);
        }
        if (n == n->parent->left) {
            rb_rotate_left(n->parent, root);
            if (rb_debug_hook) {
                rb_debug_hook("d2:rl(n.p)", n, *root);
            }
        } else {
            rb_rotate_right(n->parent, root);
            if (rb_debug_hook) {
                rb_debug_hook("d2:rr(n.p)", n, *root);
            }
        }
    }
    rb_delete3(n, root);

}

void rb_delete3(rb_node_t * n, rb_node_t ** root) {

    rb_node_t * s = rb_sibling(n);

    if (s && !n->parent->is_red &&
        !s->is_red &&
        (!s->left || !s->left->is_red) &&
        (!s->right || !s->right->is_red)) {
        s->is_red = 1;

        if (rb_debug_hook) {
            rb_debug_hook("d3:red(s)", s, *root);
        }

        rb_delete1(n->parent, root);
    } else {
        rb_delete4(n, root);
    }
}

void rb_delete4(rb_node_t * n, rb_node_t ** root) {

    rb_node_t * s = rb_sibling(n);

    if (n->parent->is_red &&
        s && !s->is_red &&
        (!s->left || !s->left->is_red) &&
        (!s->right || !s->right->is_red)) {

        s->is_red = 1;

        if (rb_debug_hook) {
            rb_debug_hook("d4:red(s)", s, *root);
        }

        n->parent->is_red = 0;

        if (rb_debug_hook) {
            rb_debug_hook("d3:blk(n.p)", n, *root);
        }

    } else {
        rb_delete5(n, root);
    }

}

void rb_delete5(rb_node_t * n, rb_node_t ** root) {

    rb_node_t * s = rb_sibling(n);

    if (s && !s->is_red) {

        if (n == n->parent->left &&
            (!s->right || !s->right->is_red) &&
            (s->left && s->left->is_red)) {

            s->is_red = 1;
            s->left->is_red = 0;
            rb_rotate_right(s, root);
            if (rb_debug_hook) {
                rb_debug_hook("d5:red(s);blk(s.l);rr(s)", s, *root);
            }

        } else if (n == n->parent->right &&
                   (!s->left || !s->left->is_red) &&
                   (s->right && s->right->is_red)) {

            s->is_red = 1;
            s->right->is_red = 0;
            rb_rotate_left(s, root);
            if (rb_debug_hook) {
                rb_debug_hook("d5:red(s);blk(s.r);rr(s)", s, *root);
            }
        }
    }

    rb_delete6(n, root);
}


void rb_delete6(rb_node_t * n, rb_node_t ** root) {

    rb_node_t * s = rb_sibling(n);
    if (!s) { return; }

    s->is_red = n->parent->is_red;
    n->parent->is_red = 0;

    if (n == n->parent->left) {
        s->right->is_red = 0;
        if (rb_debug_hook) {
            rb_debug_hook("d6:blk(s.r)", s, *root);
        }
        rb_rotate_left(n->parent, root);
        if (rb_debug_hook) {
            rb_debug_hook("d6:rl(n.p)", n, *root);
        }
    } else {
        s->left->is_red = 0;
        if (rb_debug_hook) {
            rb_debug_hook("d6:blk(s.left)", s, *root);
        }
        rb_rotate_right(n->parent, root);
        if (rb_debug_hook) {
            rb_debug_hook("d6:rr(n.p)", n, *root);
        }
    }

}

inline rb_node_t * rb_sibling(rb_node_t * n) {
    if (n == n->parent->left) {
        return n->parent->right;
    } else {
        return n->parent->left;
    }
}

rb_tree_nav_t * rb_tree_start(rb_tree_nav_t * p, rb_node_t * root) {

    rb_node_t * node = root;

    if (!root) {
        p->node = 0;
        p->next = 0;
    } else {
        while (node->left) { node = node->left; }
        p->node = node;
        p->next = rb_next_node(p->node);
    }

    return p;
}

void rb_tree_next(rb_tree_nav_t * p) {

    if (!p->next) {
        p->node = 0;
    } else {
        p->node = p->next;
        p->next = rb_next_node(p->node);
    }

}

rb_node_t * rb_next_node(rb_node_t * next) {

    rb_node_t * parent;

    if (next->right) {
        next = next->right;
        while (next->left) { next = next->left; }
        return next;
    } else if ((parent = next->parent)) {

        // we need to keep climbing up until
        // we climb up a left leg, if any, or 
        // we run out of parent.

        while (parent->right == next) {
            next = parent;
            parent = parent->parent;
            if (!parent) { break; }
        }

        return parent;

    } else {
        return 0;
    }

}

#define rb_rotate(rs,os) \
    void rb_rotate_##rs (rb_node_t * node, rb_node_t ** tree_root) { \
        rb_node_t ** alink; \
        rb_node_t * pivot; \
        \
        if (node->parent) { \
            if (node->parent->left == node) { \
                alink = &node->parent->left; \
            } else { \
                alink = &node->parent->right; \
            } \
        } else {\
            alink = 0; \
        } \
        \
        pivot = node->os; \
        node->os = pivot->rs; \
        if (node->os) { \
            node->os->parent = node; \
        } \
        pivot->rs = node; \
        pivot->parent = node->parent; \
        node->parent = pivot; \
        if (alink) { \
            *alink = pivot; \
        } else { \
            *tree_root = pivot; \
        } \
    }

rb_rotate(left, right);
rb_rotate(right, left);
