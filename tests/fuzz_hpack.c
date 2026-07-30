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
    static char output[65536];
    size_t offset = 0;
    hpack_decode_string_ext(tree, data, size, &offset, output, sizeof(output), &(size_t){0});
    return 0;
}
