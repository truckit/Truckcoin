// Copyright (c) 2013 NovaCoin Developers

#ifndef PBKDF2_H
#define PBKDF2_H

#include <stdint.h>
#include <stddef.h>

void
PBKDF2_SHA256(const uint8_t * passwd, size_t passwdlen, const uint8_t * salt,
    size_t saltlen, uint64_t c, uint8_t * buf, size_t dkLen);

#endif // PBKDF2_H
