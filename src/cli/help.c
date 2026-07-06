#include "curldbg.h"

#include <stdio.h>
#include <string.h>

#include "flags.h"

void print_help(const char *prog) {
    printf("curldbg %s -- HTTP debug client\n\n", CURLDBG_VERSION);
    printf("Usage: %s [options] <url> [url2 ...]\n\n", prog);

    const char *last_cat = NULL;
    for (int i = 0; g_flags[i].desc != NULL; i++) {
        const struct flag_info *f = &g_flags[i];
        if (last_cat == NULL || strcmp(f->category, last_cat) != 0) {
            if (last_cat != NULL) printf("\n");
            printf("%s:\n", f->category);
            last_cat = f->category;
        }
        printf("  ");
        int col = 2;
        if (f->short_name != NULL) {
            printf("%s", f->short_name);
            col += (int)strlen(f->short_name);
        }
        if (f->long_name != NULL) {
            if (f->short_name != NULL) { printf(", "); col += 2; }
            printf("%s", f->long_name);
            col += (int)strlen(f->long_name);
        }
        if (f->arg != NULL) {
            printf(" %s", f->arg);
            col += (int)strlen(f->arg) + 1;
        }
        int pad = 26 - col;
        if (pad < 1) pad = 1;
        for (int p = 0; p < pad; p++) putchar(' ');
        printf("%s\n", f->desc);
    }
    printf("\nAuthor: Pau Santana\n");
}
