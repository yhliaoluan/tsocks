#include <stdint.h>
#include <assert.h>
#include "crypto.h"
#include "memory.h"
#include "rc4.h"
#include "sstable.h"

struct ts_rc4_ctx {
    struct rc4_state enc_state;
    struct rc4_state dec_state;
};

struct ts_crypto_ctx {
    union {
        struct ts_rc4_ctx rc4;
        struct sstable_state sstable;
    };
    void (*encrypt) (struct ts_crypto_ctx *, const unsigned char *,
        unsigned char *, int);
    void (*decrypt) (struct ts_crypto_ctx *, const unsigned char *,
        unsigned char *, int);
};

static void ts_rc4_encrypt(struct ts_crypto_ctx *ctx, const unsigned char *in,
    unsigned char *out, int len) {

    rc4_crypt(&ctx->rc4.enc_state, in, out, len);
}

static void ts_rc4_decrypt(struct ts_crypto_ctx *ctx, const unsigned char *in,
    unsigned char *out, int len) {

    rc4_crypt(&ctx->rc4.dec_state, in, out, len);
}

static struct ts_crypto_ctx *ts_crypto_rc4(const unsigned char *key, int len) {
    struct ts_crypto_ctx *ctx = ts_malloc(sizeof(struct ts_crypto_ctx));
    if (ctx) {
        rc4_init(&ctx->rc4.enc_state, key, len);
        rc4_init(&ctx->rc4.dec_state, key, len);
        ctx->encrypt = ts_rc4_encrypt;
        ctx->decrypt = ts_rc4_decrypt;
    }
    return ctx;
}

static void ts_plain_crypto(struct ts_crypto_ctx *ctx, const unsigned char *in,
    unsigned char *out, int len) {

    if (out != in) {
        memcpy(out, in, len);
    }
}

static struct ts_crypto_ctx *ts_crypto_plain() {
    struct ts_crypto_ctx *ctx = ts_malloc(sizeof(struct ts_crypto_ctx));
    if (ctx) {
        ctx->encrypt = ts_plain_crypto;
        ctx->decrypt = ts_plain_crypto;
    }
    return ctx;
}

static void ts_sstable_decrypt(struct ts_crypto_ctx *ctx, const unsigned char *in,
    unsigned char *out, int len) {

    sstable_decrypt(&ctx->sstable, in, out, len);
}

static void ts_sstable_encrypt(struct ts_crypto_ctx *ctx, const unsigned char *in,
    unsigned char *out, int len) {

    sstable_encrypt(&ctx->sstable, in, out, len);
}

static struct ts_crypto_ctx *ts_crypto_sstable(const uint8_t *key, int len) {
    struct ts_crypto_ctx *ctx = ts_malloc(sizeof(struct ts_crypto_ctx));
    if (ctx) {
        sstable_init(&ctx->sstable, key, len);
        ctx->encrypt = ts_sstable_encrypt;
        ctx->decrypt = ts_sstable_decrypt;
    }
    return ctx;
}

struct ts_crypto_ctx *ts_crypto_new(const char *method, const unsigned char *key, int len) {

    if (strcmp(method, "rc4") == 0) {
        return ts_crypto_rc4(key, len);
    } else if (strcmp(method, "plain") == 0) {
        return ts_crypto_plain();
    } else if (strcmp(method, "sstable") == 0) {
        return ts_crypto_sstable(key, len);
    } else {
        return NULL;
    }
}

void ts_crypto_free(struct ts_crypto_ctx *ctx) {
    ts_free(ctx);
}

void ts_crypto_encrypt(struct ts_crypto_ctx *ctx, const unsigned char *plain,
    unsigned char *cipher, int len) {

    assert(ctx && plain && cipher);
    assert(len > 0);

    ctx->encrypt(ctx, plain, cipher, len);
}

void ts_crypto_decrypt(struct ts_crypto_ctx *ctx, const unsigned char *cipher,
    unsigned char *plain, int len) {

    assert(ctx && plain && cipher);
    assert(len > 0);

    ctx->decrypt(ctx, cipher, plain, len);
}
