#ifndef _LINUX_RC4_H_
#define _LINUX_RC4_H_

#include <stddef.h>
#include <string.h>

static void RC4(unsigned char *key, unsigned char *in, unsigned char *out, size_t len)
{
    unsigned char S[256];
    unsigned char temp;
    int i, j = 0;
    int keylen = (int)strlen((const char *)key);

    for (i = 0; i < 256; i++)
        S[i] = (unsigned char)i;

    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % keylen]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }

    i = j = 0;
    for (size_t k = 0; k < len; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        out[k] = in[k] ^ S[(S[i] + S[j]) % 256];
    }
}

#endif
