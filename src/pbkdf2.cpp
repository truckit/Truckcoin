// Copyright (c) 2013 NovaCoin Developers

#include "pbkdf2.h"
#include "hmac_sha256.h"
#include <string.h>

static inline uint32_t
be32dec(const void *pp)
{
    const uint8_t *p = (uint8_t const *)pp;

    return ((uint32_t)(p[3]) + ((uint32_t)(p[2]) << 8) +
        ((uint32_t)(p[1]) << 16) + ((uint32_t)(p[0]) << 24));
}

static inline void
be32enc(void *pp, uint32_t x)
{
    uint8_t * p = (uint8_t *)pp;

    p[3] = x & 0xff;
    p[2] = (x >> 8) & 0xff;
    p[1] = (x >> 16) & 0xff;
    p[0] = (x >> 24) & 0xff;
}

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
void
PBKDF2_SHA256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
    size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen)
{
    CHMAC_SHA256 baseCtx = CHMAC_SHA256(passwd, passwdlen);
    CHMAC_SHA256 PShctx = CHMAC_SHA256(passwd, passwdlen);
    CHMAC_SHA256 hctx = CHMAC_SHA256(passwd, passwdlen);
    size_t i;
    uint8_t ivec[4];
    uint8_t U[CHMAC_SHA256::OUTPUT_SIZE];
    uint8_t T[CHMAC_SHA256::OUTPUT_SIZE];
    uint64_t j;
    unsigned int k;
    size_t clen;

    /* Compute HMAC state after processing P and S. */
    PShctx.Write(salt, saltlen);

    /* Iterate through the blocks. */
    for (i = 0; i * 32 < dkLen; i++) {
        /* Generate INT(i + 1). */
        be32enc(ivec, (uint32_t)(i + 1));

        /* Compute U_1 = PRF(P, S || INT(i)). */
        PShctx.Copy(&hctx);
        hctx.Write(ivec, 4);
        hctx.Finalize(U);

        /* T_i = U_1 ... */
        memcpy(T, U, CHMAC_SHA256::OUTPUT_SIZE);

        for (j = 2; j <= c; j++) {
            /* Compute U_j. */
            baseCtx.Copy(&hctx);
            hctx.Write(U, CHMAC_SHA256::OUTPUT_SIZE);
            hctx.Finalize(U);

            /* ... xor U_j ... */
            for (k = 0; k < CHMAC_SHA256::OUTPUT_SIZE; k++)
                T[k] ^= U[k];
        }

        /* Copy as many bytes as necessary into buf. */
        clen = dkLen - i * CHMAC_SHA256::OUTPUT_SIZE;
        if (clen > CHMAC_SHA256::OUTPUT_SIZE)
            clen = CHMAC_SHA256::OUTPUT_SIZE;
        memcpy(&buf[i * CHMAC_SHA256::OUTPUT_SIZE], T, clen);
    }

}
