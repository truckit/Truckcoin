// Copyright (c) 2009-2012 The Bitcoin developers
// Copyright (c) 2011-2013 The PPCoin developers
// Copyright (c) 2013-2023 The Truckcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// The synchronized checkpoint system is first developed by Sunny King for
// ppcoin network in 2012, giving cryptocurrency developers a tool to gain
// additional network protection against 51% attack.
//
// Primecoin also adopts this security mechanism, and the enforcement of
// checkpoints is explicitly granted by user, thus granting only temporary
// consensual central control to developer at the threats of 51% attack.
//
// Concepts
//
// In the network there can be a privileged node known as 'checkpoint master'.
// This node can send out checkpoint messages signed by the checkpoint master
// key. Each checkpoint is a block hash, representing a block on the blockchain
// that the network should reach consensus on.
//
// Besides verifying signatures of checkpoint messages, each node also verifies
// the consistency of the checkpoints. If a conflicting checkpoint is received,
// it means either the checkpoint master key is compromised, or there is an
// operator mistake. In this situation the node would discard the conflicting
// checkpoint message and display a warning message. This precaution controls
// the damage to network caused by operator mistake or compromised key.
//
// Operations
//
// Checkpoint master key can be established by using the 'makekeypair' command
// The public key in source code should then be updated and private key kept
// in a safe place.
//
// Any node can be turned into checkpoint master by setting the 'checkpointkey'
// configuration parameter with the private key of the checkpoint master key.
// Operator should exercise caution such that at any moment there is at most
// one node operating as checkpoint master. When switching master node, the
// recommended procedure is to shutdown the master node and restart as
// regular node, note down the current checkpoint by 'getcheckpoint', then
// compare to the checkpoint at the new node to be upgraded to master node.
// When the checkpoint on both nodes match then it is safe to switch the new
// node to checkpoint master.
//
// The configuration parameter 'checkpointdepth' specifies how many blocks
// should the checkpoints lag behind the latest block in auto checkpoint mode.
// A depth of 6 is the default auto checkpoint policy and offers the greatest
// protection against 51% attack.
//

#include "checkpoints.h"
#include "checkpointsync.h"

#include "bitcoinrpc.h"
#include "txdb.h"
#include "main.h"
#include "uint256.h"
//#include "base58.h"

// sync-checkpoint master key
const std::string CSyncCheckpoint::strMasterPubKey = "048c9c6ba1370ab16eff70814f1a8783108bf1a031b2028561bb11d83fcf95f82878932428b4ccafb95a35c0a704a534222de05afdf1e839127822789136ffd709";
std::string CSyncCheckpoint::strMasterPrivKey = "";

// synchronized checkpoint (centrally broadcasted)
uint256 hashSyncCheckpoint = 0;
uint256 hashPendingCheckpoint = 0;
CSyncCheckpoint checkpointMessage;
CSyncCheckpoint checkpointMessagePending;
uint256 hashInvalidCheckpoint = 0;
CCriticalSection cs_hashSyncCheckpoint;

// get last synchronized checkpoint
CBlockIndex* GetLastSyncCheckpoint()
{
    LOCK(cs_hashSyncCheckpoint);
    if (!mapBlockIndex.count(hashSyncCheckpoint))
        error("GetSyncCheckpoint: block index missing for current sync-checkpoint %s", hashSyncCheckpoint.ToString().c_str());
    else
        return mapBlockIndex[hashSyncCheckpoint];
    return NULL;
}

// only descendant of current sync-checkpoint is allowed
bool ValidateSyncCheckpoint(uint256 hashCheckpoint)
{
    CBlockIndex* pindexSyncCheckpoint = nullptr;
    CBlockIndex* pindexCheckpointRecv = nullptr;

    {
        LOCK2(cs_main, cs_hashSyncCheckpoint);
        if (!mapBlockIndex.count(hashSyncCheckpoint))
            return error("ValidateSyncCheckpoint: block index missing for current sync-checkpoint %s", hashSyncCheckpoint.ToString().c_str());
        if (!mapBlockIndex.count(hashCheckpoint))
            return error("ValidateSyncCheckpoint: block index missing for received sync-checkpoint %s", hashCheckpoint.ToString().c_str());

        pindexSyncCheckpoint = mapBlockIndex[hashSyncCheckpoint];
        pindexCheckpointRecv = mapBlockIndex[hashCheckpoint];
    }

    if (pindexCheckpointRecv->nHeight <= pindexSyncCheckpoint->nHeight)
    {
        // Received an older checkpoint, trace back from current checkpoint
        // to the same height of the received checkpoint to verify
        // that current checkpoint should be a descendant block
        CBlockIndex* pindex = pindexSyncCheckpoint;
        while (pindex->nHeight > pindexCheckpointRecv->nHeight)
            if (!(pindex = pindex->pprev))
                return error("ValidateSyncCheckpoint: pprev1 null - block index structure failure");
        if (pindex->GetBlockHash() != hashCheckpoint)
        {
            hashInvalidCheckpoint = hashCheckpoint;
            LOCK(cs_hashSyncCheckpoint);
            return error("ValidateSyncCheckpoint: new sync-checkpoint %s is conflicting with current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());// sync-checkpoint master key
        }
        return false; // ignore older checkpoint
    }

    // Received checkpoint should be a descendant block of the current
    // checkpoint. Trace back to the same height of current checkpoint
    // to verify.
    CBlockIndex* pindex = pindexCheckpointRecv;
    while (pindex->nHeight > pindexSyncCheckpoint->nHeight)
        if (!(pindex = pindex->pprev))
            return error("ValidateSyncCheckpoint: pprev2 null - block index structure failure");

    {
        LOCK(cs_hashSyncCheckpoint);
        if (pindex->GetBlockHash() != hashSyncCheckpoint)
        {
            hashInvalidCheckpoint = hashCheckpoint;
            return error("ValidateSyncCheckpoint: new sync-checkpoint %s is not a descendant of current sync-checkpoint %s", hashCheckpoint.ToString().c_str(), hashSyncCheckpoint.ToString().c_str());
        }
    }
    return true;
}

bool WriteSyncCheckpoint(const uint256& hashCheckpoint)
{
    if (!pblocktree->WriteSyncCheckpoint(hashCheckpoint))
        return error("WriteSyncCheckpoint(): failed to write to txdb sync checkpoint %s", hashCheckpoint.ToString().c_str());
    if (!pblocktree->Sync())
        return error("WriteSyncCheckpoint(): failed to commit to txdb sync checkpoint %s", hashCheckpoint.ToString().c_str());

    hashSyncCheckpoint = hashCheckpoint;
    return true;
}

bool AcceptPendingSyncCheckpoint()
{
    {
        LOCK2(cs_main, cs_hashSyncCheckpoint);
        bool havePendingCheckpoint = hashPendingCheckpoint != uint256() && mapBlockIndex.count(hashPendingCheckpoint);
        if (!havePendingCheckpoint)
            return false;
    }

    uint256 hashPendingCheckpointTmp;
    {
        LOCK(cs_hashSyncCheckpoint);
        hashPendingCheckpointTmp = hashPendingCheckpoint;
    }

    if (!ValidateSyncCheckpoint(hashPendingCheckpointTmp))
    {
        LOCK(cs_hashSyncCheckpoint);
        hashPendingCheckpoint = uint256();
        checkpointMessagePending.SetNull();
        return false;
    }

    {
        LOCK2(cs_main, cs_hashSyncCheckpoint);
        if (!chainActive.Contains(mapBlockIndex[hashPendingCheckpoint]))
            return false;
    }

    {
        LOCK(cs_hashSyncCheckpoint);
        if (!WriteSyncCheckpoint(hashPendingCheckpoint)) {
            return error("AcceptPendingSyncCheckpoint(): failed to write sync checkpoint %s", hashPendingCheckpoint.ToString().c_str());
        }

        hashPendingCheckpoint = uint256();
        checkpointMessage = checkpointMessagePending;
        checkpointMessagePending.SetNull();

        // relay the checkpoint
        if (!checkpointMessage.IsNull())
        {
            for (CNode* pnode : vNodes)
                checkpointMessage.RelayTo(pnode);
        }
    }

    return true;
}


/* Checkpoint master: selects a block for checkpointing according to the policy */
uint256 AutoSelectSyncCheckpoint()
{
    /* No immediate checkpointing on either PoW or PoS blocks,
    * select by depth in the main chain rather than block time */
    const CBlockIndex *pindex = chainActive.Tip();
    while(pindex->pprev && (pindex->nHeight + (int)GetArg("-checkpointdepth", CHECKPOINT_DEFAULT_DEPTH)) > chainActive.Height())
        pindex = pindex->pprev;
    return(pindex->GetBlockHash());
}

// Check against synchronized checkpoint
// Use fast & non-full check
bool CheckSyncCheckpoint(const uint256& hashBlock, const CBlockIndex* pindexPrev)
{
    // Testnet has no checkpoints
    if (fTestNet) 
        return true;

    LOCK(cs_hashSyncCheckpoint);
    int nHeight = pindexPrev->nHeight + 1;
    assert(mapBlockIndex.count(hashSyncCheckpoint));        
    CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(mapBlockIndex);
    return !(pcheckpoint && nHeight < pcheckpoint->nHeight);
}

bool WantedByPendingSyncCheckpoint(uint256 hashBlock)
{
    LOCK(cs_hashSyncCheckpoint);
    if (hashPendingCheckpoint == 0)
        return false;
    if (hashBlock == hashPendingCheckpoint)
        return true;
    if (mapOrphanBlocks.count(hashPendingCheckpoint) 
        && hashBlock == WantedByOrphan(mapOrphanBlocks[hashPendingCheckpoint]))
        return true;
    return false;
}

// reset synchronized checkpoint to last hardened checkpoint
bool ResetSyncCheckpoint()
{
    LOCK(cs_hashSyncCheckpoint);
    const uint256& hash = Checkpoints::GetLatestHardenedCheckpoint();
    if (mapBlockIndex.count(hash) && !chainActive.Contains(mapBlockIndex[hash]))
    {
        // checkpoint block accepted but not yet in main chain
        printf("ResetSyncCheckpoint: SetBestChain to hardened checkpoint %s\n", hash.ToString().c_str());
        CBlock block;
        if (!ReadBlockFromDisk(block, mapBlockIndex[hash]))
            return error("ResetSyncCheckpoint: ReadFromDisk failed for hardened checkpoint %s", hash.ToString().c_str());
        CValidationState state;
        if (!SetBestChain(state, mapBlockIndex[hash]))
        {
            return error("ResetSyncCheckpoint: SetBestChain failed for hardened checkpoint %s", hash.ToString().c_str());
        }
    }
    else if(!mapBlockIndex.count(hash))
    {
        // checkpoint block not yet accepted
        hashPendingCheckpoint = hash;
        checkpointMessagePending.SetNull();
        printf("ResetSyncCheckpoint: pending for sync-checkpoint %s\n", hashPendingCheckpoint.ToString().c_str());
    }

    if (!WriteSyncCheckpoint((mapBlockIndex.count(hash) && chainActive.Contains(mapBlockIndex[hash]))? hash : hashGenesisBlock))
        return error("ResetSyncCheckpoint: failed to write sync checkpoint %s", hash.ToString().c_str());
    printf("ResetSyncCheckpoint: sync-checkpoint reset to %s\n", hashSyncCheckpoint.ToString().c_str());
    return true;
}

void AskForPendingSyncCheckpoint(CNode* pfrom)
{
    LOCK(cs_hashSyncCheckpoint);
    if (pfrom && hashPendingCheckpoint != 0 && (!mapBlockIndex.count(hashPendingCheckpoint)) && (!mapOrphanBlocks.count(hashPendingCheckpoint)))
        pfrom->AskFor(CInv(MSG_BLOCK, hashPendingCheckpoint));
}

// Verify sync checkpoint master pubkey and reset sync checkpoint if changed
bool CheckCheckpointPubKey()
{
    std::string strPubKey = "";
    // if checkpoint master key changed must reset sync-checkpoint
    if (!pblocktree->ReadCheckpointPubKey(strPubKey) || strPubKey != CSyncCheckpoint::strMasterPubKey)
    {
        // write checkpoint master key to db
        if (!pblocktree->WriteCheckpointPubKey(CSyncCheckpoint::strMasterPubKey))
            return error("CheckCheckpointPubKey() : failed to write new checkpoint master key to db");
        if (!pblocktree->Sync())
            return error("CheckCheckpointPubKey() : failed to commit new checkpoint master key to db");
        if (!ResetSyncCheckpoint())
            return error("CheckCheckpointPubKey() : failed to reset sync-checkpoint");
    }
    return true;
}

bool SetCheckpointPrivKey(std::string strPrivKey)
{
    // Test signing a sync-checkpoint with genesis block
    CSyncCheckpoint checkpoint;
    checkpoint.hashCheckpoint = hashGenesisBlock;
    CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
    sMsg << (CUnsignedSyncCheckpoint)checkpoint;
    checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

//    CBitcoinSecret vchSecret;
//    if (!vchSecret.SetString(strPrivKey))
//        return error("SetCheckpointPrivKey(): Invalid private key encoding");
//    CKey key = vchSecret.GetKey();
//    if (!key.IsValid())
//        return error("SetCheckpointPrivKey(): Private key outside allowed range");

    std::vector<unsigned char> vchPrivKey = ParseHex(strPrivKey);
    CKey key;
    key.SetPrivKey(CPrivKey(vchPrivKey.begin(), vchPrivKey.end()), 0); // if key is not correct openssl may crash

    if (!key.Sign(Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig))
        return error("SetCheckpointPrivKey(): Unable to sign checkpoint, check private key?");

    // Test signing successful, proceed
    CSyncCheckpoint::strMasterPrivKey = strPrivKey;
    return true;
}

bool SendSyncCheckpoint(uint256 hashCheckpoint)
{
    CSyncCheckpoint checkpoint;
    checkpoint.hashCheckpoint = hashCheckpoint;
    CDataStream sMsg(SER_NETWORK, PROTOCOL_VERSION);
    sMsg << (CUnsignedSyncCheckpoint)checkpoint;
    checkpoint.vchMsg = std::vector<unsigned char>(sMsg.begin(), sMsg.end());

    if (CSyncCheckpoint::strMasterPrivKey.empty())
        return error("SendSyncCheckpoint: Checkpoint master key unavailable.");

//    CBitcoinSecret vchSecret;
//    if (!vchSecret.SetString(CSyncCheckpoint::strMasterPrivKey))
//        return error("SendSyncCheckpoint(): Invalid private key encoding");
//    CKey key = vchSecret.GetKey();
//    if (!key.IsValid())
//        return error("SendSyncCheckpoint(): Private key outside allowed range");

    std::vector<unsigned char> vchPrivKey = ParseHex(CSyncCheckpoint::strMasterPrivKey);
    CKey key;
    key.SetPrivKey(CPrivKey(vchPrivKey.begin(), vchPrivKey.end()), 0); // if key is not correct openssl may crash

    if (!key.Sign(Hash(checkpoint.vchMsg.begin(), checkpoint.vchMsg.end()), checkpoint.vchSig))
        return error("SendSyncCheckpoint: Unable to sign checkpoint, check private key?");

    if(!checkpoint.ProcessSyncCheckpoint(NULL))
    {
        printf("WARNING: SendSyncCheckpoint: Failed to process checkpoint.\n");
        return false;
    }

    // Relay checkpoint
    {
        LOCK(cs_vNodes);
        for (CNode* pnode : vNodes)
            checkpoint.RelayTo(pnode);
    }
    return true;
}

// Is the sync-checkpoint outside maturity window?
bool IsMatureSyncCheckpoint()
{
    LOCK(cs_hashSyncCheckpoint);
    // sync-checkpoint should always be accepted block
    assert(mapBlockIndex.count(hashSyncCheckpoint));
    const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];
    return (chainActive.Height() >= pindexSync->nHeight + nCoinbaseMaturity || pindexSync->GetBlockTime() + nStakeMinAge < GetAdjustedTime());
}

// Is the sync-checkpoint too old?
bool IsSyncCheckpointTooOld(unsigned int nSeconds)
{
    LOCK(cs_hashSyncCheckpoint);
    // sync-checkpoint should always be accepted block
    assert(mapBlockIndex.count(hashSyncCheckpoint));
    const CBlockIndex* pindexSync = mapBlockIndex[hashSyncCheckpoint];
    return (pindexSync->GetBlockTime() + nSeconds < GetAdjustedTime());
}

// ppcoin: find block wanted by given orphan block
uint256 WantedByOrphan(const CBlock* pblockOrphan)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblockOrphan->hashPrevBlock))
        pblockOrphan = mapOrphanBlocks[pblockOrphan->hashPrevBlock];
    return pblockOrphan->hashPrevBlock;
}

// verify signature of sync-checkpoint message
bool CSyncCheckpoint::CheckSignature()
{
    std::string strMasterPubKey = CSyncCheckpoint::strMasterPubKey;
    CPubKey key(ParseHex(strMasterPubKey));
    if (!key.Verify(Hash(vchMsg.begin(), vchMsg.end()), vchSig))
        return error("CSyncCheckpoint::CheckSignature() : verify signature failed");

    // Now unserialize the data
    CDataStream sMsg(vchMsg, SER_NETWORK, PROTOCOL_VERSION);
    sMsg >> *static_cast<CUnsignedSyncCheckpoint*>(this);
    return true;
}

// process synchronized checkpoint
bool CSyncCheckpoint::ProcessSyncCheckpoint(CNode* pfrom)
{
    if (!CheckSignature())
        return false;

    LOCK(cs_hashSyncCheckpoint);
    if (!mapBlockIndex.count(hashCheckpoint))
    {
        // We haven't received the checkpoint chain, keep the checkpoint as pending
        hashPendingCheckpoint = hashCheckpoint;
        checkpointMessagePending = *this;
        printf("ProcessSyncCheckpoint: pending for sync-checkpoint %s\n", hashCheckpoint.ToString().c_str());
        // Ask this guy to fill in what we're missing
        if (pfrom)
        {
            PushGetBlocks(pfrom, chainActive.Tip(), hashCheckpoint);
            // ask directly as well in case rejected earlier by duplicate
            // proof-of-stake because getblocks may not get it this time
            pfrom->AskFor(CInv(MSG_BLOCK, mapOrphanBlocks.count(hashCheckpoint)? WantedByOrphan(mapOrphanBlocks[hashCheckpoint]) : hashCheckpoint));
        }
        return false;
    }

    if (!ValidateSyncCheckpoint(hashCheckpoint))
        return false;

    CBlockIndex* pindexCheckpoint = mapBlockIndex[hashCheckpoint];
    if (!chainActive.Contains(pindexCheckpoint))
    {
        // checkpoint chain received but not yet main chain
        CBlock block;
        if (!ReadBlockFromDisk(block, pindexCheckpoint))
            return error("ProcessSyncCheckpoint: ReadFromDisk failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        CValidationState state;
        if (!SetBestChain(state, pindexCheckpoint))
        {
            hashInvalidCheckpoint = hashCheckpoint;
            return error("ProcessSyncCheckpoint: SetBestChain failed for sync checkpoint %s", hashCheckpoint.ToString().c_str());
        }
    }

    if (!WriteSyncCheckpoint(hashCheckpoint))
        return error("ProcessSyncCheckpoint(): failed to write sync checkpoint %s", hashCheckpoint.ToString().c_str());
    checkpointMessage = *this;
    hashPendingCheckpoint = 0;
    checkpointMessagePending.SetNull();
    printf("ProcessSyncCheckpoint: sync-checkpoint at %s\n", hashCheckpoint.ToString().c_str());
    return true;
}
