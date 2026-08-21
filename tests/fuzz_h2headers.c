#include "http2_internal.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static struct huff_node *tree = NULL;
static int tree_alloc = 0;

__attribute__((constructor))
static void init_tree(void) {
    huff_tree_init(&tree, &tree_alloc);
}

int send_rst_stream(struct connection *conn, uint32_t stream_id,
                    uint32_t error_code, char *error, size_t error_len) {
    (void)conn;
    (void)stream_id;
    (void)error_code;
    (void)error;
    (void)error_len;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (tree == NULL || size == 0) return 0;

    struct h2_connection h2;
    memset(&h2, 0, sizeof(h2));
    h2.huff_tree = tree;
    h2.dyn_table.max_size = H2_MAX_DYNAMIC_TABLE_SIZE;
    h2.dyn_table.capacity = 16;
    h2.dyn_table.entries = calloc(h2.dyn_table.capacity,
                                  sizeof(struct h2_hpack_entry));
    if (h2.dyn_table.entries == NULL) return 0;

    struct h2_stream st;
    struct response_info ri;
    memset(&st, 0, sizeof(st));
    memset(&ri, 0, sizeof(ri));
    st.out = &ri;

    parse_h2_header_block(&h2, &st, NULL, 1, data, size, NULL, 0);

    for (size_t i = 0; i < h2.dyn_table.count; i++)
        hpack_entry_free(&h2.dyn_table.entries[i]);
    free(h2.dyn_table.entries);
    return 0;
}
