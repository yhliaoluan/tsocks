#ifndef _TS_CRYPTO_H_
#define _TS_CRYPTO_H_

#define TS_CRYPTO_RC4     1

struct ts_crypto_ctx;

struct ts_crypto_ctx *ts_crypto_new(int method, const unsigned char *key, int len);
void ts_crypto_free(struct ts_crypto_ctx *ctx);

void ts_crypto_encrypt(struct ts_crypto_ctx *ctx, const unsigned char *plain,
    unsigned char *cipher, int len);

void ts_crypto_decrypt(struct ts_crypto_ctx *ctx, const unsigned char *cipher,
    unsigned char *plain, int len);
#endif
