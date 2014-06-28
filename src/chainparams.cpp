// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "core.h"
#include "protocol.h"
#include "util.h"

//
// Main network
//

unsigned int pnSeed[] =
{
    0x12345678
};

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        pchMessageStart[0] = 0x13;
        pchMessageStart[1] = 0xff;
        pchMessageStart[2] = 0x98;
        pchMessageStart[3] = 0x01;
        vAlertPubKey = ParseHex("0480a759cdc99d76706cc0da5a32b30e70bdf1b568981f481f73fb09ea5b1213cf141688bc78bfe8e7d1532d0c1e1bb0f772b8c6bd84d483c75cc12e602015f6c0");
        nDefaultPort = 10678;
        nRPCPort = 10680;
        bnProofOfWorkLimit[ALGO_SHA256D]  = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_SCRYPT]   = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_GROESTL]  = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_SKEIN]    = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_QUBIT]    = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_X11]      = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_QUARK]    = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_GROESTL2] = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_BLAKE256] = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_X13]      = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_SCRYPTN]  = CBigNum(~uint256(0) >> 20);
        bnProofOfWorkLimit[ALGO_KECCAK]   = CBigNum(~uint256(0) >> 20);
        nSubsidyHalvingInterval = 524160 / 6; // 2 months @ 1 minute blocks

        // Build the genesis block. Note that the output of the genesis coinbase cannot
        // be spent as it did not originally exist in the database.
  
        const char* pszTimestamp = "20140628-Guardian-Britain closer to EU exit";
        CTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = nMinSubsidy;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("0461265581c3e32fbd14a1ec74a840ba312a8106be2a3992964d807ad33825735a02e3ee7438579c76cbb1d470326acf7fa4bf876251f4595ecacffab0a02cd79c") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = BLOCK_VERSION_DEFAULT;
        genesis.nTime    = nGenesisTime;
        genesis.nBits    = 0x1e0fffff;
        genesis.nNonce   = 2095476325;
        
        //// debug print
        hashGenesisBlock = genesis.GetHash();
        /*
        while (hashGenesisBlock > bnProofOfWorkLimit[ALGO_SHA256D].getuint256()){
            if (++genesis.nNonce==0) break;
            hashGenesisBlock = genesis.GetHash();
        }

        printf("MAIN: %s\n", hashGenesisBlock.ToString().c_str());
        printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        printf("%x\n", bnProofOfWorkLimit[ALGO_SHA256D].GetCompact());
        genesis.print();
        */
        
        assert(hashGenesisBlock == uint256("0x000005b29ea428d2fe73103832897e3124ae11fd5e1774fce28273a9b11dc663"));
        assert(genesis.hashMerkleRoot == uint256("0x858ffa2bcb471c3ed676034236eb749ecf46e660cc27cae3d14e25128089b5a9"));

        vSeeds.push_back(CDNSSeedData("seed1.spectrumcoin.net", "seed1.spectrumcoin.net"));
        vSeeds.push_back(CDNSSeedData("seed2.spectrumcoin.net", "seed2.spectrumcoin.net"));
        vSeeds.push_back(CDNSSeedData("seed3.spectrumcoin.net", "seed3.spectrumcoin.net"));
        vSeeds.push_back(CDNSSeedData("seed4.spectrumcoin.net", "seed4.spectrumcoin.net"));
        vSeeds.push_back(CDNSSeedData("seed5.spectrumcoin.net", "seed5.spectrumcoin.net"));
        vSeeds.push_back(CDNSSeedData("seed6.spectrumcoin.net", "seed6.spectrumcoin.net"));
        vSeeds.push_back(CDNSSeedData("seed7.spectrumcoin.net", "seed7.spectrumcoin.net"));
        vSeeds.push_back(CDNSSeedData("seed8.spectrumcoin.net", "seed8.spectrumcoin.net"));

        base58Prefixes[PUBKEY_ADDRESS] = 63;
        base58Prefixes[SCRIPT_ADDRESS] = 8;
        base58Prefixes[SECRET_KEY] = 190;

        // Convert the pnSeeds array into usable address objects.
        for (unsigned int i = 0; i < ARRAYLEN(pnSeed); i++)
        {
            // It'll only connect to one or two seed nodes because once it connects,
            // it'll get a pile of addresses with newer timestamps.
            // Seed nodes are given a random 'last seen time' 
            const int64 nTwoDays = 2 * 24 * 60 * 60;
            struct in_addr ip;
            memcpy(&ip, &pnSeed[i], sizeof(ip));
            CAddress addr(CService(ip, GetDefaultPort()));
            addr.nTime = GetTime() - GetRand(nTwoDays) - nTwoDays;
            vFixedSeeds.push_back(addr);
        }
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet (v3)
//
class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        pchMessageStart[0] = 0x02;
        pchMessageStart[1] = 0xf1;
        pchMessageStart[2] = 0xa3;
        pchMessageStart[3] = 0x09;
        vAlertPubKey = ParseHex("04fb693f9cb6ed5e4fee81cd49f4317b5fdab6ba0ec6a9770fde76a9fd5a3344a6646d09acb1782852a8a2f43233a2e2a1d4136b5d9e7d3567c39fa0dfe17cabba");
        nDefaultPort = 20678;
        nRPCPort = 20680;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1403049000;
        genesis.nNonce = 419614808;
        
        //// debug print
        hashGenesisBlock = genesis.GetHash();
        /*
        while (hashGenesisBlock > bnProofOfWorkLimit[ALGO_SHA256D].getuint256()){
            if (++genesis.nNonce==0) break;
           hashGenesisBlock = genesis.GetHash();
        }

        printf("TEST: %s\n", hashGenesisBlock.ToString().c_str());
        printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        genesis.print();
        */
        
        assert(hashGenesisBlock == uint256("0x000002265ed77512ddd79046b196aa7c33d0ead690902bf3dbce83f75a6ceee9"));

        vFixedSeeds.clear();
        vSeeds.clear();
        vSeeds.push_back(CDNSSeedData("testseed1.spectrumcoin.net", "testseed1.spectrumcoin.net"));

        base58Prefixes[PUBKEY_ADDRESS] = 31;
        base58Prefixes[SCRIPT_ADDRESS] = 141;
        base58Prefixes[SECRET_KEY] = 159;

    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0x0f;
        pchMessageStart[2] = 0xa5;
        pchMessageStart[3] = 0x5a;
        nSubsidyHalvingInterval = 150;
        bnProofOfWorkLimit[ALGO_SHA256D]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_SCRYPT]   = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_GROESTL]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_SKEIN]    = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_QUBIT]    = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_X11]      = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_QUARK]    = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_GROESTL2] = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_BLAKE256] = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_X13]      = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_SCRYPTN]  = CBigNum(~uint256(0) >> 1);
        bnProofOfWorkLimit[ALGO_KECCAK]   = CBigNum(~uint256(0) >> 1);
        genesis.nTime = 1403049001;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 4;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 18444;
        strDataDir = "regtest";
        
        //// debug print
        hashGenesisBlock = genesis.GetHash();
        /*
        while (hashGenesisBlock > bnProofOfWorkLimit[ALGO_SHA256D].getuint256()){
            if (++genesis.nNonce==0) break;
            hashGenesisBlock = genesis.GetHash();
        }

        printf("REG: %s\n", hashGenesisBlock.ToString().c_str());
        printf("%s\n", genesis.hashMerkleRoot.ToString().c_str());
        genesis.print();
        */

        assert(hashGenesisBlock == uint256("0x28164384ba58b31bdad300e5f606bca098551dfd2774af82b037559790c33abf"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.

        base58Prefixes[PUBKEY_ADDRESS] = 0;
        base58Prefixes[SCRIPT_ADDRESS] = 5;
        base58Prefixes[SECRET_KEY] = 128;
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
