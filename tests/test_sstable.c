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
    unsigned char cipher[32];
    char plain2[32];
    printf("%s\n", plain);
    sstable_encrypt(&state, plain, cipher, 32);
    int i;
    for (i = 0; i < 5; i++) {
        printf("%02X ", cipher[i]);
    }
    printf("\n");
    sstable_decrypt(&state, cipher, plain2, 32);
    printf("%s\n", plain2);
    printf("mem size %u\n", ts_mem_size());
    return 0;
}
