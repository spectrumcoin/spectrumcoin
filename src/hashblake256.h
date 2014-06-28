// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_HASHBLAKE256_H
#define BITCOIN_HASHBLAKE256_H

#include "uint256.h"
#include "serialize.h"
#include "sph_blake256.h"
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <vector>
#include <string>

template<typename T1>
inline uint256 HashBlake256(const T1 pbegin, const T1 pend)
{
    sph_BLAKE256_blake256_context     ctx_blake;
    static unsigned char pblank[1];
    uint256 hash1;
    sph_BLAKE256_blake256_init(&ctx_blake);
    sph_BLAKE256_blake256 (&ctx_blake, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_BLAKE256_blake256_close(&ctx_blake, static_cast<void*>(&hash1));
    return hash1;
}

#endif
