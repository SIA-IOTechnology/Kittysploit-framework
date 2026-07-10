#ifndef _LINUX_CHACHA_H_
#define _LINUX_CHACHA_H_

#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t input[16];
} chacha_ctx;

#define ROTL32(v, n) (((v) << (n)) | ((v) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d) \
    a += b; d ^= a; d = ROTL32(d, 16); \
    c += d; b ^= c; b = ROTL32(b, 12); \
    a += b; d ^= a; d = ROTL32(d, 8);  \
    c += d; b ^= c; b = ROTL32(b, 7);

static void chacha_keysetup(chacha_ctx *x, const unsigned char *k, unsigned long keybits, unsigned long ivbits)
{
    const char *constants = (keybits == 256) ? "expand 32-byte k" : "expand 16-byte k";

    x->input[0] = *(uint32_t *)(constants + 0);
    x->input[1] = *(uint32_t *)(constants + 4);
    x->input[2] = *(uint32_t *)(constants + 8);
    x->input[3] = *(uint32_t *)(constants + 12);
    if (keybits == 256) {
        x->input[4] = *(uint32_t *)(k + 0);
        x->input[5] = *(uint32_t *)(k + 4);
        x->input[6] = *(uint32_t *)(k + 8);
        x->input[7] = *(uint32_t *)(k + 12);
        x->input[8] = *(uint32_t *)(k + 16);
        x->input[9] = *(uint32_t *)(k + 20);
        x->input[10] = *(uint32_t *)(k + 24);
        x->input[11] = *(uint32_t *)(k + 28);
    } else {
        x->input[4] = *(uint32_t *)(k + 0);
        x->input[5] = *(uint32_t *)(k + 4);
        x->input[6] = *(uint32_t *)(k + 8);
        x->input[7] = *(uint32_t *)(k + 12);
        x->input[8] = x->input[4];
        x->input[9] = x->input[5];
        x->input[10] = x->input[6];
        x->input[11] = x->input[7];
    }
    (void)ivbits;
}

static void chacha_ivsetup(chacha_ctx *x, const unsigned char *iv)
{
    x->input[12] = 0;
    x->input[13] = 0;
    x->input[14] = *(uint32_t *)(iv + 0);
    x->input[15] = *(uint32_t *)(iv + 4);
}

static void chacha_encrypt_bytes(chacha_ctx *ctx, const unsigned char *m, unsigned char *c, unsigned long bytes)
{
    unsigned long i;
    unsigned char *ctarget = c;
    unsigned char tmp[64];

    for (;;) {
        uint32_t x[16];
        for (i = 0; i < 16; ++i)
            x[i] = ctx->input[i];

        for (i = 20; i > 0; i -= 2) {
            QUARTERROUND(x[0], x[4], x[8], x[12])
            QUARTERROUND(x[1], x[5], x[9], x[13])
            QUARTERROUND(x[2], x[6], x[10], x[14])
            QUARTERROUND(x[3], x[7], x[11], x[15])
            QUARTERROUND(x[0], x[5], x[10], x[15])
            QUARTERROUND(x[1], x[6], x[11], x[12])
            QUARTERROUND(x[2], x[7], x[8], x[13])
            QUARTERROUND(x[3], x[4], x[9], x[14])
        }

        for (i = 0; i < 16; ++i)
            x[i] += ctx->input[i];

        for (i = 0; i < 16; ++i)
            *(uint32_t *)(tmp + 4 * i) = x[i];

        ctx->input[12]++;
        if (!ctx->input[12])
            ctx->input[13]++;

        if (bytes <= 64) {
            for (i = 0; i < bytes; ++i)
                ctarget[i] = m[i] ^ tmp[i];
            return;
        }
        for (i = 0; i < 64; ++i)
            ctarget[i] = m[i] ^ tmp[i];
        bytes -= 64;
        m += 64;
        ctarget += 64;
    }
}

#endif
