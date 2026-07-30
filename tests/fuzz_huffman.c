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
    unsigned char output[4096];
    huffman_decode(tree, data, size, output, sizeof(output));
    return 0;
}
