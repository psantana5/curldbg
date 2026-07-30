#include "curldbg.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    char *url = malloc(size + 1);
    if (url == NULL) return 0;
    memcpy(url, data, size);
    url[size] = '\0';

    struct url_info info;
    parse_url(url, &info);

    char buf[2048];
    format_url(&info, buf, sizeof(buf));
    format_absolute_uri(&info, buf, sizeof(buf));
    format_host_header(&info, buf, sizeof(buf));

    free(url);
    return 0;
}
