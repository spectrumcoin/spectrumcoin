#ifndef HASHKECCACK_H
#define HASHKECCACK_H

#include "uint256.h"
#include "sph_keccak.h"

template<typename T1>
inline uint256 HashKeccak(const T1 pbegin, const T1 pend)
{
    sph_keccak256_context ctx_keccak;
    static unsigned char pblank[1];
    uint256 hash;

    sph_keccak256_init(&ctx_keccak);
    sph_keccak256 (&ctx_keccak, (pbegin == pend ? pblank : static_cast<const void*>(&pbegin[0])), (pend - pbegin) * sizeof(pbegin[0]));
    sph_keccak256_close(&ctx_keccak, static_cast<void*>(&hash));

    return hash;
}

#endif // HASHKECCACK_H
