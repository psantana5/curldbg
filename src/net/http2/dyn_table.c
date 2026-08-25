#define _GNU_SOURCE
#include "http2_internal.h"

#include <stdlib.h>
#include <string.h>

void hpack_entry_free(struct h2_hpack_entry *e) {
    free(e->name);
    free(e->value);
    e->name = NULL;
    e->value = NULL;
    e->name_len = 0;
    e->value_len = 0;
}

static void hpack_table_evict_until(struct h2_hpack_table *dyn, size_t limit) {
    while (dyn->size > limit && dyn->count > 0) {
        struct h2_hpack_entry *last = &dyn->entries[dyn->count - 1];
        dyn->size -= last->name_len + last->value_len + 32;
        hpack_entry_free(last);
        dyn->count--;
    }
}

void hpack_table_evict(struct h2_hpack_table *dyn) {
    hpack_table_evict_until(dyn, dyn->max_size);
}

int hpack_table_add(struct h2_hpack_table *dyn, const char *name, size_t name_len,
                    const char *value, size_t value_len) {
    if (value_len > SIZE_MAX - 32 || name_len > SIZE_MAX - 32 - value_len)
        return -1;
    size_t entry_size = name_len + value_len + 32;
    if (entry_size > dyn->max_size) {
        for (size_t i = 0; i < dyn->count; i++)
            hpack_entry_free(&dyn->entries[i]);
        dyn->count = 0;
        dyn->size = 0;
        return 0;
    }

    hpack_table_evict_until(dyn, dyn->max_size - entry_size);

    if (dyn->count >= dyn->capacity) {
        size_t new_cap = dyn->capacity * 2;
        struct h2_hpack_entry *new_entries = realloc(dyn->entries,
                                            new_cap * sizeof(struct h2_hpack_entry));
        if (new_entries == NULL) return -1;
        dyn->entries = new_entries;
        dyn->capacity = new_cap;
    }

    if (dyn->count > 0) {
        memmove(&dyn->entries[1], &dyn->entries[0],
                dyn->count * sizeof(struct h2_hpack_entry));
    }

    struct h2_hpack_entry *e = &dyn->entries[0];
    e->name = malloc(name_len + 1);
    e->value = malloc(value_len + 1);
    if (e->name == NULL || e->value == NULL) {
        free(e->name); free(e->value);
        return -1;
    }
    memcpy(e->name, name, name_len);
    e->name[name_len] = '\0';
    memcpy(e->value, value, value_len);
    e->value[value_len] = '\0';
    e->name_len = name_len;
    e->value_len = value_len;
    dyn->count++;
    dyn->size += entry_size;
    return 0;
}

void hpack_table_set_max_size(struct h2_hpack_table *dyn, uint32_t new_size) {
    dyn->max_size = new_size;
    hpack_table_evict(dyn);
}

int get_table_entry(struct h2_hpack_table *dyn, int index,
                    const char **name, size_t *name_len,
                    const char **value, size_t *value_len) {
    if (index >= 1 && index < 62) {
        const struct h2_static_entry *e = get_static_entry(index);
        if (e == NULL) return -1;
        *name = e->name;
        *name_len = e->name_len;
        *value = e->value;
        *value_len = e->value_len;
        return 0;
    }
    int dyn_idx = index - 62;
    if (dyn_idx >= 0 && (size_t)dyn_idx < dyn->count) {
        const struct h2_hpack_entry *e = &dyn->entries[dyn_idx];
        *name = e->name;
        *name_len = e->name_len;
        *value = e->value;
        *value_len = e->value_len;
        return 0;
    }
    return -1;
}
