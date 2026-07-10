#ifndef _LINUX_BASE64_H_
#define _LINUX_BASE64_H_

#include <stddef.h>
#include <string.h>

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64decode(unsigned char *out, const char *in, int inlen)
{
    int i, j;
    unsigned char buf[4];
    int outlen = 0;

    for (i = 0; i < inlen; i += 4) {
        for (j = 0; j < 4; j++) {
            const char *p = strchr(b64_table, in[i + j]);
            if (p == NULL) {
                if (in[i + j] == '=')
                    buf[j] = 0;
                else
                    return -1;
            } else {
                buf[j] = (unsigned char)(p - b64_table);
            }
        }

        out[outlen++] = (buf[0] << 2) | (buf[1] >> 4);
        if (in[i + 2] != '=')
            out[outlen++] = (buf[1] << 4) | (buf[2] >> 2);
        if (in[i + 3] != '=')
            out[outlen++] = (buf[2] << 6) | buf[3];
    }

    return outlen;
}

#endif
