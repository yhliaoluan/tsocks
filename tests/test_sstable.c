#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sstable.h"

int main(int argc, char **argv) {

    if (argc < 2) {
        printf("no key\n");
        return 1;
    }
    struct sstable_state state;
    sstable_init(&state, argv[1], strlen(argv[1]));

    char plain[32] = "Hello";
    char cipher[32];
    char plain2[32];
    sstable_encrypt(&state, plain, cipher, 32);
    sstable_decrypt(&state, cipher, plain2, 32);
    printf("%s to %s\n", plain, plain2);
    printf("mem size %u\n", ts_mem_size());
    return 0;
}
