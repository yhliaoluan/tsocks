#include "sstable.h"
#include "md5.h"
#include "memory.h"

static long compare(uint8_t x, uint8_t y, uint64_t a, int i) {
    return (int64_t)(a % (uint64_t)(x + i)) - (int64_t)(a % (uint64_t)(y + i));
}

static void merge_sort(uint8_t *array, size_t len, uint64_t a, int j, uint8_t *out) {
    memcpy(out, array, len);
    if (len == 1) return;
    int middle = len / 2;
    uint8_t *left = ts_malloc(middle);
    int i;
    for (i = 0; i < middle; i++) {
        left[i] = array[i];
    }
    uint8_t *right = ts_malloc(len - middle);
    for (i = 0; i < len - middle; i++)
    {
        right[i] = array[i + middle];
    }
    merge_sort(array, middle, a, j, left);
    merge_sort(array + middle, len - middle, a, j, right);

    int leftptr = 0;
    int rightptr = 0;

    int k;
    for (k = 0; k < len; k++)
    {
        if (rightptr == len - middle || ((leftptr < middle)
                && (compare(left[leftptr], right[rightptr], a, j) <= 0))) {
            out[k] = left[leftptr];
            leftptr++;
        }
        else if (leftptr == middle || ((rightptr < len - middle)
                && (compare(right[rightptr], left[leftptr], a, j)) <= 0)) {
            out[k] = right[rightptr];
            rightptr++;
        }
    }

    ts_free(left);
    ts_free(right);
}

void sstable_init(struct sstable_state *state, const uint8_t *key, size_t len) {
    uint8_t md5[MD5_DIGEST_LENGTH];
    ts_md5(key, len, md5);
    uint64_t a = *((uint64_t *)md5);
    int i;
    for (i = 0; i < 256; i++) {
        state->encrypt_table[i] = i;
    }
    uint8_t *tmp = ts_malloc(256);
    for (i = 1; i < 1024; i++) {
        merge_sort(state->encrypt_table, 256, a, i, tmp);
        memcpy(state->encrypt_table, tmp, 256);
    }
    for (i = 0; i < 256; i++) {
        state->decrypt_table[state->encrypt_table[i]] = i;
    }
    ts_free(tmp);
}

void sstable_encrypt(struct sstable_state *state, const uint8_t *in,
    uint8_t *out, size_t len) {

    int i;
    for (i = 0; i < len; i++) {
        out[i] = state->encrypt_table[in[i]];
    }
}
void sstable_decrypt(struct sstable_state *state, const uint8_t *in,
    uint8_t *out, size_t len) {
    int i;
    for (i = 0; i < len; i++) {
        out[i] = state->decrypt_table[in[i]];
    }
}
