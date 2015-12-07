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

    unsigned char cipher[5] = { 0x50, 0x1B, 0xE2, 0xE2, 0x21 };
    unsigned char plain[5];
    sstable_decrypt(&state, cipher, plain, 5);
    int i;
    for (i = 0; i < 5; i++) {
        printf("%02X ", plain[i]);
    }
    printf("\n");
    printf("mem size %u\n", ts_mem_size());
    return 0;
}
