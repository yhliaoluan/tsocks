#include <stdio.h>
#include <string.h>
#include "md5.h"

int main(int argc, char **argv) {
    unsigned char md5[MD5_DIGEST_LENGTH];
    int i;
    ts_md5(argv[1], strlen(argv[1]), md5);
    for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
        printf("%02X ", md5[i]);
    }
    printf("\n");
    return 0;
}
