#include "curldbg.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

ssize_t connection_read(struct connection *conn, void *buf, size_t len,
                        char *error, size_t error_len) {
    (void)conn; (void)buf; (void)len; (void)error; (void)error_len;
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > HEADER_MAX) return 0;

    char *buf = malloc(size + 1);
    if (buf == NULL) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    struct response_info out;
    parse_response_headers(buf, &out);

    free(buf);
    return 0;
}
