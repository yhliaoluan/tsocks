#define TS_DETECT_MEM_LEAK

#include <stdio.h>
#include "utils/memory.h"

int main(int argc, char **argv) {
    void *p = ts_malloc(10);
    printf("%p, remain %zu\n", p, ts_get_total_size());
    ts_free(p);
    printf("remain %zu\n", ts_get_total_size());
    return 0;
}
