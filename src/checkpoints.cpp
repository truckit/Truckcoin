// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013-2023 The Truckcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/assign/list_of.hpp> // for 'map_list_of()'

#include "checkpoints.h"

#include "main.h"
#include "txdb.h"
#include "uint256.h"

namespace Checkpoints
{
    typedef std::map<int, uint256> MapCheckpoints;   // hardened checkpoints

    //
    // What makes a good checkpoint block?
    // + Is surrounded by blocks with reasonable timestamps
    //   (no blocks before with a timestamp after, none after with
    //    timestamp before)
    // + Contains no strange transactions
    //
    static MapCheckpoints mapCheckpoints =
        boost::assign::map_list_of
    ( 0, hashGenesisBlockOfficial )
    ( 10, uint256("0x0000074074af28e73189ae5767b706246be2e0827c46d97a61178394aec877cf"))
    ( 20000, uint256("0x0000000022a1ac4173866d701c6c4b56cb54b18055d21d32c82d7438a07921b7"))
    ( 21001, uint256("0x6355bfcdab1a337cbeaf1dadfb4da57bac72e421a111d8d20ecde1409f74d913"))
    ( 44007, uint256("0x343842864ed219dbadfa263581c21ac6e4a29a4d20bd2eca10b01522dc081dfa"))
    ( 68521, uint256("0xdc9caf0c710a56075eea1f40c5ed8cdc5e3f0989334495cc5e01caca82efa7dd"))
    ( 147422, uint256("0x6ad97a9200475191701a7bf1c96c8a4ad190523311bbccce432761252bf69a03"))
    ( 444444, uint256("0x53c8cb49ae3f51dcac3c24a9a590c46e6013b5e4759baf797b00d0f11ed7cf22"))
    ( 587986, uint256("0x660ab7bd56793ce88dd8cd8a1c80468ae65b116e719e702cfc55517c74b47ce2"))
    ( 588340, uint256("0x1ef0215c46ddb8ed12045ae763d3a583189f6cd0b8909de5d24f0e0bf43c6bec"))
    ( 799993, uint256("0xd4b3a9c2b5ed4f815454d4ff5393d0eab50d75dc5d59e692f33b7369b414b299"))
    ( 1008090, uint256("0xd2643e836e5337634591014c486a23d770416cae5916189638158e60a41fc755"))
    ( 1120009, uint256("0xe6a66281b84538c8d431260b5f022946ed1c4fe84d77484388b5bd8186361c20"))
    ( 1248969, uint256("0x169e5ff72d885204d53ec631d7035e47f5492ac1609aa3d12ca5acc4715792c6"))
    ( 1292791, uint256("0x24549c4f523207e968c82a47af9e60121bef90046678e505569527197f94ff18"))
    ( 1391163, uint256("0xdc4542ce0d84337a831d9c708f6159ad36a42c347cb6a6a1a9f068dc35cdec0e"))
    ( 1523355, uint256("0x2e688fae305403dff445ea0979df45c1960e13240868bc8c0a41cb62704e0a56"))
    ( 1693797, uint256("0x396655bdf578547149053731903728edb2eb5be6eb10919b01628fc478ace7fc"))
    ( 1776009, uint256("0x05fafa2b307eaefcd53d02866995c000ad06ac7927ad50d7338b5f184b339121"))
    ( 1937023, uint256("0x64a6012dd6a8769b670476a9cb607ba54d95d0bff18b65950dd77d8b5e5c99e9"))
    ( 2000023, uint256("0x2c7f7171774693c40084ebe4c2c21dafc0f70ca3cecc8b21df3e01f0b432af37"))
    ( 2302323, uint256("0xd2b2fe77c78b8d0eeb7bfe4dbcd4fd86c73c01b2acae2cd398699e66c8a112f8"))
    ( 2602323, uint256("0x1254d68efa16779c67fb19529e1114d8797c4f1784730213cf7d1de4a9bc1fe4"))
    ( 2902323, uint256("0xb3d15773cd2bf9261ca339e63ce7d63b675529b15af4824de3dc38bd2098e0e1"))
    ( 3130023, uint256("0xeb542dfb23e6c2ff6fdd74526b8c2301ea785206c3426f701c1a718f9240cef5"))
    ;

    bool CheckHardened(int nHeight, const uint256& hash)
    {
        MapCheckpoints& checkpoints = mapCheckpoints;

        MapCheckpoints::const_iterator i = checkpoints.find(nHeight);
        if (i == checkpoints.end()) return true;
        return hash == i->second;
    }

    int GetTotalBlocksEstimate()
    {
        MapCheckpoints& checkpoints = mapCheckpoints;

        return checkpoints.rbegin()->first;
    }

    CBlockIndex* GetLastCheckpoint(const std::map<uint256, CBlockIndex*>& mapBlockIndex)
    {
        MapCheckpoints& checkpoints = mapCheckpoints;

        for(auto it = checkpoints.rbegin(); it != checkpoints.rend(); ++it)
        {
            const uint256& hash = it->second;
            auto t = mapBlockIndex.find(hash);
            if (t != mapBlockIndex.end())
                return t->second;
        }
        return NULL;
    }

    uint256 GetLatestHardenedCheckpoint()
    {
        MapCheckpoints& checkpoints = mapCheckpoints;
        return (checkpoints.rbegin()->second);
    }
}
