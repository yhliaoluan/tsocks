#ifndef _TS_SSTABLE_H_
#define _TS_SSTABLE_H_
#include <stdint.h>
#include <stdlib.h>

struct sstable_state {
    uint8_t encrypt_table[256];
    uint8_t decrypt_table[256];
};

void sstable_init(struct sstable_state *state, const uint8_t *key, size_t len);
void sstable_encrypt(struct sstable_state *state, const uint8_t *in,
    uint8_t *out, size_t len);
void sstable_decrypt(struct sstable_state *state, const uint8_t *in,
    uint8_t *out, size_t len);

#endif
