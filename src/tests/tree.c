
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/time.h>
#include "lib/rb_tree.h"
#include "tests.h"

typedef struct {
    int val;
    rb_node_t t;
} test_t;

typedef struct {
    char *buf;
    int size;
    int len;
} buf_t;

typedef struct {
    test_t *where;
    int c_black;
} nav_t;

static int t_cmp(rb_node_t *, void *);

static char *tree_to_string(rb_node_t *);

static void tree_to_string_r(rb_node_t *, buf_t *);

static void validate_rb(rb_node_t *);

static void validate_rb_r(rb_node_t *, int, rb_node_t *, int);

static int *make_random(int c);

static void my_rb_hook(char *, void *, void *);

static int tval[] = {1, 3, 5, 2, 4, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, -1, 0};
static int dval[] = {3, 14, 9, 6, 1, 10, 7, 2, 15, 13, 8, 0};

static int r1_a[] = {218, 648, 602, 0};
static int r2_a[] = {997, 520, 999, 291, 211, 0};

int STRESS_NO = 10000;

int debug = 1;

#define REGR(name, adds, ddds) do { \
    iDBG("Testing regression %s", name); \
    rb_node_t * tree = 0; \
    { \
    int * i = adds; \
    while (*i) { \
        rb_tree_search_t aux; \
        test_t * e = (test_t*)malloc(sizeof(test_t)); \
        e->val = *i; \
        iDBG("Searching for node with value %d", *i); \
        if (rb_find(&tree, i, t_cmp, &aux)) { \
        iERR("node not expected to be found:%d", *i); \
        } \
        if (aux.node) { \
        iDBG("Will add to node %d", ((test_t*)aux.node)->val); \
        } \
        rb_insert(&e->t, &aux, &tree); \
        bux = tree_to_string(tree); \
        iDBG("%s", bux); \
        free(bux); \
        validate_rb(tree); \
        i++; \
    } \
    } \
    if (ddds) { \
        int * i = dval; \
        while (*i) { \
            rb_tree_search_t aux; \
            int test_val = *(i++); \
            iDBG("Searching for to be deleted node %d", test_val); \
            if (!rb_find(&tree, &test_val, t_cmp, &aux)) { \
                iERR("Node %d was expected to be found", test_val); \
            } \
            iDBG("Deleting node %d", test_val); \
            rb_delete(&tree, aux.node); \
            bux = tree_to_string(tree); \
            iDBG("%s", bux); \
            free(bux); \
            validate_rb(tree); \
            if (rb_find(&tree, &test_val, t_cmp, &aux)) { \
                iERR("Node %d was deleted, but is found", test_val); \
            } \
        } \
    } \
} while(0)

int main(int argc, char **argv) {

    rb_node_t * tree = 0;
    char *bux;
    rb_debug_hook = my_rb_hook;
    int do_stress = argc > 1 && !strcmp("-s", argv[1]);

    iDBG("For the printed tree text, go to http://manticore.2y.net/rbtree");

    struct timeval tv;
    gettimeofday(&tv, 0);
    srandom((unsigned)tv.tv_sec);

    // load the tree up
    {
        int *i = tval;
        while (*i) {
            rb_tree_search_t aux;
            test_t *e = (test_t *) malloc(sizeof(test_t));
            e->val = *i;
            iDBG("Searching for node with value %d", *i);
            if (rb_find(&tree, i, t_cmp, &aux)) {
                iERR("node not expected to be found:%d", *i);
            }
            if (aux.node) {
                iDBG("Will add to node %d", ((test_t *) aux.node)->val);
            }
            rb_insert(&e->t, &aux, &tree);
            bux = tree_to_string(tree);
            iDBG("%s", bux);
            free(bux);
            validate_rb(tree);
            i++;
        }
    }

    if (!tree) { return 1; }

    int deleting_val = (TO_RB_NODE2(test_t, tree, t))->val;
    rb_delete(&tree, tree);
    bux = tree_to_string(tree);
    iDBG("%s", bux);
    free(bux);
    {
        rb_tree_search_t aux;
        if (rb_find(&tree, &deleting_val, t_cmp, &aux)) {
            iERR("Node %d was deleted, but is found", TO_RB_NODE2(test_t, tree, t)->val);
        }
    }
    validate_rb(tree);

    {
        int *i = dval;
        while (*i) {

            rb_tree_search_t aux;
            int test_val = *(i++);
            iDBG("Searching for to be deleted node %d", test_val);
            if (!rb_find(&tree, &test_val, t_cmp, &aux)) {
                iERR("Node %d was expected to be found", test_val);
            }
            iDBG("Deleting node %d", test_val);
            rb_delete(&tree, aux.node);
            bux = tree_to_string(tree);
            iDBG("%s", bux);
            free(bux);
            validate_rb(tree);
            if (rb_find(&tree, &test_val, t_cmp, &aux)) {
                iERR("Node %d was deleted, but is found", test_val);
            }

        }
    }

    // REGR("double-red", ({218,648,602}), 3, ({}), 0);
    REGR("double-red", r1_a, 0);
    REGR("segv-add", r2_a, 0);

    if (do_stress) {

        iDBG("Starting stress with %d", STRESS_NO);

        int *buildMap = make_random(STRESS_NO);
        int *deleteMap = make_random(STRESS_NO);
        tree = 0;

        // load the tree up
        {
            int i;
            for (i = 0; i < STRESS_NO; i++) {
                rb_tree_search_t aux;
                test_t *e = (test_t *) malloc(sizeof(test_t));
                e->val = buildMap[i];
                iDBG("Searching for node with value %d", e->val);
                if (rb_find(&tree, &e->val, t_cmp, &aux)) {
                    iERR("node not expected to be found:%d", e->val);
                }
                if (aux.node) {
                    iDBG("Will add to node %d", ((test_t *) aux.node)->val);
                }
                rb_insert(&e->t, &aux, &tree);
                bux = tree_to_string(tree);
                iDBG("%s", bux);
                free(bux);
                validate_rb(tree);
            }
        }

        for (int i = 0; i < STRESS_NO; i++) {

            rb_tree_search_t aux;
            int test_val = deleteMap[i];
            iDBG("Searching for to be deleted node %d", test_val);
            if (!rb_find(&tree, &test_val, t_cmp, &aux)) {
                iERR("Node %d was expected to be found", test_val);
            }
            iDBG("Deleting node %d", test_val);
            rb_delete(&tree, aux.node);
            bux = tree_to_string(tree);
            iDBG("%s", bux);
            free(bux);
            validate_rb(tree);
            if (rb_find(&tree, &test_val, t_cmp, &aux)) {
                iERR("Node %d was deleted, but is found", test_val);
            }

        }

    }


    iDBG("all ok");
    return 0;

}

int t_cmp(rb_node_t *n1, void *n2) {

    // return ((test_t *) n1)->val - ((test_t *) n2)->val;
    return TO_RB_NODE2(test_t, n1, t)->val - *(int*)n2;
}

#define ADD_CHAR(c) do { \
    if (out->len == out->size) { \
    out->size += 512; \
    if (!out->buf) { \
        out->buf = malloc(out->size); \
    } else { \
        out->buf = realloc(out->buf, out->size); \
    } \
    } \
    out->buf[out->len++] = (c); \
    } while(0)

// format of the dump is:
// NODE := COLOR VALUE CHAIN CHAIN
// CHAIN := { [NODE] }
char *tree_to_string(rb_node_t * root) {

    buf_t _out;
    buf_t *out = &_out;

    _out.buf = 0;
    _out.size = 0;
    _out.len = 0;

    tree_to_string_r(root, out);
    ADD_CHAR(0);

    return _out.buf;

}

void tree_to_string_r(rb_node_t *node, buf_t *out) {

    char n[30];
    char *v;

    if (!node) { return; }

    ADD_CHAR(node->is_red ? 'R' : 'B');

    sprintf(n, "%d", TO_RB_NODE2(test_t, node, t)->val);
    for (v = n; *v; v++) {
        ADD_CHAR(*v);
    }

    ADD_CHAR('{');
    tree_to_string_r(node->left, out);
    ADD_CHAR('}');
    ADD_CHAR('{');
    tree_to_string_r(node->right, out);
    ADD_CHAR('}');

}

void validate_rb(rb_node_t *node) {
    validate_rb_r(node, 0, 0, 0);
}

void validate_rb_r(rb_node_t *node, int level, rb_node_t *comp, int leftis1) {

    int bcount = 0;
    int mcount = 0;
    nav_t *nav = 0;
    int n_size = 0;
    int n_len = 0;
    test_t *cur;

    if (!node) { return; }

    int node_val = TO_RB_NODE2(test_t, node, t)->val;

    if (!level && node->is_red) {
        iERR("root node must be black");
    }

    if (!level && node->parent) {
        iERR("root's parent must be null!");
    }

    if (node->is_red) {
        // if I'm red, my children must be black.
        if (node->left && node->left->is_red) {
            iERR("red node %d left child is red!", node_val);
        }
        if (node->right && node->right->is_red) {
            iERR("red node %d right child is red!", node_val);
        }
    }

    // check parent links
    if (node->left && node->left->parent != node) {
        iERR("node %d left child has wrong parent!", node_val);
    }
    if (node->right && node->right->parent != node) {
        iERR("node %d right child has wrong parent!", node_val);
    }

    cur = TO_RB_NODE2(test_t, node, t);

    while (1) {


        if (comp) {
            int comp_val = TO_RB_NODE2(test_t, comp, t)->val;
            if (leftis1 && cur->val >= comp_val) {
                iERR("Node %d is on left path of node %d,"
                        " but it's value is gte", cur->val, comp_val);
            }
            if (!leftis1 && cur->val <= comp_val) {
                iERR("Node %d is on right path of node %d,"
                        " but it's value is lte", cur->val, comp_val);
            }
        }

        // count node color
        if (!cur->t.is_red) {
            bcount++;
        }

#define CHECK(side) \
        do {  \
            if (!cur->t.side) { \
                if (mcount == 0) { \
                    mcount = bcount; \
                } else { \
                    if (mcount != bcount) { \
                        iERR("Reaching from node %d to node %d, on " #side " side, expected %d black count, got %d", \
                                node_val, cur->val, mcount, bcount); \
                    } \
                } \
            } \
        } while (0)

        CHECK(left);
        CHECK(right);

        // are we at a leaf?
        if (!cur->t.left && !cur->t.right) {
            // yes.

            if (n_len) {
                nav_t *fork = nav + --n_len;
                bcount = fork->c_black;
                cur = fork->where;
                continue;
            }
            // we are at a bottom, and there is no path memory,
            // so we are done.
            if (nav) { free(nav); }
            break;
        }

        // are we at a fork?
        if (cur->t.left && cur->t.right) {
            nav_t *fork;
            if (n_len == n_size) {
                n_size += 10;
                if (nav) {
                    nav = realloc(nav, n_size * sizeof(nav_t));
                } else {
                    nav = malloc(n_size * sizeof(nav_t));
                }
            }
            fork = nav + n_len++;
            fork->where = TO_RB_NODE2(test_t, cur->t.right, t);
            fork->c_black = bcount;
        }

        if (cur->t.left) {
            cur = TO_RB_NODE2(test_t, cur->t.left, t);
        } else {
            cur = TO_RB_NODE2(test_t, cur->t.right, t);
        }

    }

    validate_rb_r(node->left, level + 1, node, 1);
    validate_rb_r(node->right, level + 1, node, 0);

}


void my_rb_hook(char *op, void *node, void *root) {


    char *st = tree_to_string(root);

    iDBG("-> OP %s on node %d",
            op, node ? ((test_t *) node)->val : -1);

    iDBG("------ tree changed to be ------\n%s\n----- end -----", st);
    free(st);

}

int *make_random(int c) {

    int *r = f_malloc(c * sizeof(int));

    double p = (double) c / (double) RAND_MAX;

    for (int i = 0; i < c; i++) {

        int v = (int) (((double) random()) * p);
        while (1) {
            if (!r[v]) {
                r[v] = i + 1;
                iDBG("%d -> %d", i + 1, v);
                break;
            }
            if (++v == c) { v = 0; }
        }

    }

    return r;

}
