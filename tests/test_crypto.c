#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "crypto.h"

int main(int argc, char **argv) {

    if (argc < 2) {
        printf("please input key and text");
        return 1;
    }

    struct ts_crypto_ctx *enc_ctx = ts_crypto_new(TS_CRYPTO_RC4, argv[1], strlen(argv[1]));

    char cipher[256];
    int len = strlen(argv[2]);
    ts_crypto_encrypt(enc_ctx, argv[2], cipher, len);

    struct ts_crypto_ctx *dec_ctx = ts_crypto_new(TS_CRYPTO_RC4, argv[1], strlen(argv[1]));

    char plain2[256] = {0};
    ts_crypto_decrypt(dec_ctx, cipher, plain2, len);

    printf("Before encrypt:%s, after decrypt:%s\n", argv[2], plain2);
}
