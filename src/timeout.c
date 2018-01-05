
#include "internal.h"
#include "debug.h"

static int timeout_cmp(rb_node_t * node, void * val_ptr);

void schedule_stream_timeout(xl4bus_connection_t * conn, stream_t * stream, unsigned timeout_ms) {

    remove_stream_timeout(conn, stream);

    if (!timeout_ms) {
        if (!(timeout_ms = conn->stream_timeout_ms)) {
            return;
        }
    }

    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;

    stream->times_out_at_ms = pf_ms_value() + timeout_ms;

    rb_tree_search_t search;
    if (rb_find(&i_conn->timeout_tree, &stream->times_out_at_ms, timeout_cmp, &search)) {
        pf_abort("Found the impossible to find");
    }

    rb_insert(&stream->rb_timeout, &search, &i_conn->timeout_tree);
    ref_stream(stream);

}

void remove_stream_timeout(xl4bus_connection_t * conn, stream_t * stream) {

    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;
    if (stream->times_out_at_ms) {
        rb_delete(&i_conn->timeout_tree, &stream->rb_timeout);
        stream->times_out_at_ms = 0;
        unref_stream(stream);
    }

}

int timeout_cmp(rb_node_t * node, void * val_ptr) {

    // we never return 0, because there is no equality.

    if (TO_RB_NODE2(stream_t, node, rb_timeout)->times_out_at_ms < *(uint64_t*)val_ptr) {
        return -1;
    }
    return 1;

}

void release_timed_out_streams(xl4bus_connection_t * conn) {

    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;
    rb_tree_nav_t nav;
    uint64_t now = pf_ms_value();

    for (rb_tree_start(&nav, i_conn->timeout_tree); nav.node; rb_tree_next(&nav)) {

        stream_t * stream = TO_RB_NODE2(stream_t, nav.node, rb_timeout);
        if (stream->times_out_at_ms <= now) {
            DBG("Stream %04x timed out, releasing", stream->stream_id);
            release_stream(conn, stream, XL4SCR_TIMED_OUT);
        }

    }

}

int next_stream_timeout(xl4bus_connection_t * conn) {

    connection_internal_t * i_conn = (connection_internal_t*)conn->_private;
    rb_tree_nav_t nav;
    rb_tree_start(&nav, i_conn->timeout_tree);
    if (nav.node) {

        uint64_t now = pf_ms_value();
        uint64_t trigger_time = TO_RB_NODE2(stream_t, nav.node, rb_timeout)->times_out_at_ms;

        if (trigger_time < now) {
            return 0;
        }

        return (int)(trigger_time - now);

    }

    return -1;

}
