#include "curldbg.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static struct huff_node *tree = NULL;
static int tree_alloc = 0;

__attribute__((constructor))
static void init_tree(void) {
    huff_tree_init(&tree, &tree_alloc);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (tree == NULL || size == 0) return 0;

    unsigned char output[4096];
    size_t offset = 0;
    uint64_t len;

    hpack_decode_int(data, size, &offset, 7, &len);
    huffman_decode(tree, data, size, output, sizeof(output));

    return 0;
}
