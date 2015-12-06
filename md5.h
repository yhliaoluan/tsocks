#ifndef _TS_MD5_H_
#define _TS_MD5_H_

#include <openssl/md5.h>

int ts_md5(const unsigned char *buf, size_t len, unsigned char *md5) {
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, buf, len);
    MD5_Final(md5, &c);
    return 0;
}

#endif
