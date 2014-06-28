// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef HASH_GROESTL
#define HASH_GROESTL

#include "uint256.h"
#include "serialize.h"
#include "sph_groestl.h"

#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <vector>


template<typename T1>
inline uint256 HashMyriadGroestl(const T1 pbegin, const T1 pend)
{
    sph_groestl512_context ctx_groestl;
    static unsigned char pblank[1];

    uint512 hash1;
    uint256 hash2;

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512(&ctx_groestl, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_groestl512_close(&ctx_groestl, static_cast<void*>(&hash1));
    
    SHA256((unsigned char*)&hash1, 64, (unsigned char*)&hash2);
    
    return hash2;
}

template<typename T1>
inline uint256 HashGroestl2(const T1 pbegin, const T1 pend)
{
    sph_groestl512_context  ctx_gr[2];
    static unsigned char pblank[1];
    uint512 hash[2];

    sph_groestl512_init(&ctx_gr[0]);
    sph_groestl512 (&ctx_gr[0], (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_groestl512_close(&ctx_gr[0], static_cast<void*>(&hash[0]));

	sph_groestl512_init(&ctx_gr[1]);
	sph_groestl512(&ctx_gr[1],static_cast<const void*>(&hash[0]),64);
	sph_groestl512_close(&ctx_gr[1],static_cast<void*>(&hash[1]));

    return hash[1].trim256();
}


#endif
