#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "crypto.h"

int main(int argc, char **argv) {

    if (argc < 1) {
        printf("please input key\n");
        return 1;
    }

    char buf[256] = "Hello";
    struct ts_crypto_ctx *enc_ctx = ts_crypto_new(TS_CRYPTO_RC4, argv[1], strlen(argv[1]));

    ts_crypto_encrypt(enc_ctx, buf, buf, 256);

    struct ts_crypto_ctx *dec_ctx = ts_crypto_new(TS_CRYPTO_RC4, argv[1], strlen(argv[1]));

    ts_crypto_decrypt(dec_ctx, buf, buf, 256);

    printf("after decrypt %s\n", buf);
}
