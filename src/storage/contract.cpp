
#include <storage/contract.h>

#include "leveldb/db.h"

#include <fstream>
#include <primitives/block.h>
#include <wallet/coincontrol.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>
// #include <contract/cpor/cpor.h>
// #include <storage/cpor.h>

#include <cstdlib>
#include <ctime>
#include <net.h>
#include <netbase.h>
#include <netmessagemaker.h>
#include <storage/ipfs_interface.h>

using namespace std;
using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::system_clock;


#define COLDPOOL_MAX 10
#define WORKINGSET_SIZE 30
#define CHALLENGE_TIME 10
#define CHALLENGE_BLOCKS 10

/**
 * @brief Used for memory leak monitor-- remove later
 * 
 * @param line 
 * @return int 
 */
static int parseLine(char* line)
{
    // This assumes that a digit will be found and the line ends in " Kb".
    int i = strlen(line);
    const char* p = line;
    while (*p < '0' || *p > '9')
        p++;
    line[i - 3] = '\0';
    i = atoi(p);
    return i;
}

static int getValue()
{ // Note: this value is in KB!
    FILE* file = fopen("/proc/self/status", "r");
    int result = -1;
    char line[128];

    while (fgets(line, 128, file) != NULL) {
        if (strncmp(line, "VmSize:", 7) == 0) {
            result = parseLine(line);
            break;
        }
    }
    fclose(file);
    return result;
}

void removeBlock(std::string hash)
{
    fs::path blockPath = GetBlocksDir() / strprintf("blk_%s.dat", hash);

    if (fs::exists(blockPath)) {
        LogPrintf("RM block %s\n", hash);
        fs::remove(blockPath);
    }
}

std::vector<CStorageMessage> CBlockContractManager::pushColdPool()
{
    LOCK(cs_main);
    std::vector<CStorageMessage> vDeployList;
    fs::path csvPath = GetDataDir() / "upload.csv";
    std::fstream csvStream;
    csvStream.open(csvPath.string(), ios::app);

    ReadKey();

    LogPrintf("cold pool size: %d\n", vColdPool.size());

    int i = 0;
    int nColdPoolMax = gArgs.GetArg("-coldpool",COLDPOOL_MAX);
    for (auto& item : vColdPool) {
        if (i > nColdPoolMax) break;
        auto newTime = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();

        csvStream << newTime << "," << item.hash.ToString() << ",0\n";
        CBlock block;

        // Check if there is a block inside coldblock then do not deploy again
        if (vColdBlock.size() != 0) {
            // LogPrintf("Hash: %s\n", item.first.ToString());
            if (vColdBlock.find(item.hash) != vColdBlock.end()) {
                // LogPrintf("exist: %s, %s\n", vColdBlock.find(iter->hash)->second.hash.ToString(), iter->hash.ToString());
                removeBlock(item.hash.ToString());
                continue;// erase if exist in vcoldblock
            }
        }

        fs::path newBlockPath = GetBlocksDir() / strprintf("blk_%s.dat", item.hash.ToString());
        
        FILE* f = fsbridge::fopen(newBlockPath, "rb");
        // fseek(f, pos.nPos, SEEK_SET);
        CAutoFile filein(f, SER_DISK, CLIENT_VERSION);
        if (filein.IsNull()) continue;
        try {
            filein >> block;
        } catch (const std::exception& e) {
            continue;
        }


        // CBLOCK SERIALIZE
        json::value root;
        CppRestConstructBlockToJson(block, root);
        std::string str = root.serialize();

        // //CPOR tag


        fs::path path = GetDataDir() / "cpor";
        fs::create_directory(path);
        fs::path TagFile = path / "Tags" / item.hash.ToString().append(".tag");
        fs::path TFile = path / "Tfiles" / item.hash.ToString().append(".t");
        if (!fs::exists(TagFile)) {
            local_cpor_tag_file(str, item.hash, pkey);
            auto tagtime = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
            csvStream << tagtime << "," << item.hash.ToString() << ",1\n";
        }
        // LogPrintf("%s starts\n", item.first.ToString());

        std::vector<unsigned char> t_bin = readFileToUnsignedChar(TFile.string());
        // mTagFile.insert(pair<uint256, FILE*>(item.GetHash(),fsbridge::fopen(path,"r")));
        CPOR_challenge* pchallenge =  cpor_challenge_file(item.hash.ToString(), pkey);
        std::vector<unsigned char> challenge = SerializeChallenge(pchallenge);
        destroy_cpor_challenge(pchallenge);
        // std::cout <<"Challenge" << HexStr(challenge) <<std::endl;
        // Push To IPFS & get CID back
        CStorageMessage message;

        message.CID = AddToIPFS(str);
        message.TagCID = AddToIPFS(HexStr(readFileToUnsignedChar(TagFile.string())));
        message.firstChallengeCID = AddToIPFS(HexStr(challenge));
        message.tFileCID = AddToIPFS(HexStr(t_bin));
        message.hash = item.hash;
        
        vDeployList.push_back(message);
        ++i;
    }

    // Find Contract To deploy
    // If yes:
    // std::cout << "deploy" << std::endl;
    csvStream.close();
    return vDeployList;
}

void CBlockContractManager::automaticColdPool()
{
    int nColdPoolMax = gArgs.GetArg("-coldpool",COLDPOOL_MAX);
    if (vColdPool.size() > nColdPoolMax) {
        std::vector<CStorageMessage> vDeployList = pushColdPool();
        if (vDeployList.size() == 0) return;
        LogPrintf("ColdPoolcmp\n");
        if (deployContract(vDeployList)) {
            vColdPool.erase(vColdPool.begin(), vColdPool.begin() + nColdPoolMax);
        }
    }
}

void CBlockContractManager::appendColdPool(FlatFilePos pair)
{
    int nColdPoolMax = gArgs.GetArg("-coldpool",COLDPOOL_MAX);
    if (!(vStorageContract.size() == 0 || vColdPool.size() < nColdPoolMax)) {
        // csvStream.close();
        automaticColdPool();
    }


    for (auto p : vColdPool) {
        // LogPrintf("cmp: %s,%s\n", p.first.ToString(), pair.first.ToString());
        if (p.hash == pair.hash) {
            return;
        }
    }
    vColdPool.push_back(pair);
}

void CBlockContractManager::workingSet(uint256 hash, FlatFilePos pos)
{
    // std::cout << "workingset size:" << vWorkingSet.size() <<std::endl;
    for (auto it = vWorkingSet.begin(); it != vWorkingSet.end(); ++it) {
        if (it->hash == hash) {
            auto newPair = *it;
            vWorkingSet.erase(it);
            vWorkingSet.insert(vWorkingSet.begin(), newPair);
            return;
        }
    }
    int nWorkingSet = gArgs.GetArg("-workingset",WORKINGSET_SIZE);
    if ((vWorkingSet.size() + 1) > nWorkingSet) {
        appendColdPool(vWorkingSet.back());
        vWorkingSet.pop_back();
    }
    vWorkingSet.insert(vWorkingSet.begin(),pos);
}

bool CBlockContractManager::lookupWorkingSet(FlatFilePos& pos)
{
    for (auto& it : vWorkingSet) {
        if (pos.hash == it.hash) {
            return true;
        }
    }
    return false;
}

bool CBlockContractManager::lookupColdPool(FlatFilePos& pos)
{
    // for (auto& it : vColdPool) {
    for (auto it = vColdPool.begin(); it != vColdPool.end(); it++) {
        if (pos.hash == it->hash) {
            workingSet(pos.hash, pos);
            vColdPool.erase(it);
            return true;
        }
    }
    return false;
}

void CBlockContractManager::hotColdClassifier(CBlock* block)
{
}

void CBlockContractManager::GetBackFromIPFS(CBlock& block, FlatFilePos pos)
{
    if (vColdBlock.find(pos.hash) != vColdBlock.end()) {
        LogPrintf("Get block from ipfs: CID: %s\n", vColdBlock.find(pos.hash)->second.CID);
        GetBlockFromIPFS(block, vColdBlock.find(pos.hash)->second.CID);
    }
}

// This function is used to parse node stats to map in local
static void getNodeStat(std::map<std::string, NodeId>& nodes)
{
    std::vector<CNodeStats> nodeStats;
    g_connman->GetNodeStats(nodeStats);
    for (auto& node : nodeStats) {
      LogPrintf("nodeipport: %s\n",node.addr.ToStringIPPort());
        nodes.insert(std::pair<std::string, NodeId>(node.addr.ToStringIPPort(), node.nodeid));
    }
}

bool CBlockContractManager::deployContract(std::vector<CStorageMessage>& vDeployList)
{
    // sort(vStorageContract.begin(), vStorageContract.end(), [](StorageContract& x, StorageContract& y) { return x.nReputation > y.nReputation; });
    std::fstream csvStream;
    fs::path csvPath = GetDataDir() / "upload.csv";
    csvStream.open(csvPath.string(), ios::app);
    // Test first contract ipfsvector


    std::cout << "Contract Size: " << vStorageContract.size() << std::endl;
    if (vStorageContract.size() == 0) return false;

    std::map<std::string, NodeId> nodes;
    getNodeStat(nodes);
    bool flag = false;


    LogPrintf("vDeployList size: %d\n", vDeployList.size());
    for (auto& Itemcontract : vStorageContract) {
        // LogPrintf("vipfsnode: %d\n", Itemcontract.second.vIPFSNode.size());
        if (Itemcontract.second.vIPFSNode.size() != 0) {
            for (auto& node : Itemcontract.second.vIPFSNode) {
                // CNode newNode()
                // std::cout << "discontruct ipfsnode vector" << std::endl;
                CAddress addrConnect;
                LogPrintf("ip: %s\n",node.second.ip);
                if (nodes.find(node.second.ip) == nodes.end()) {
                    g_connman->AddNode(node.second.ip);
                    getNodeStat(nodes);
                }
                NodeId nodeid = nodes.find(node.second.ip)->second;
                // LogPrintf("Node IP: %s, node id: %d\n", node.second.ip, nodeid);
                std::vector<CStorageMessage> vMessage;
                for (auto& list : vDeployList) {
                    g_connman->ForNodeMsg(nodeid, list);
                    CBlockEach blockEach;
                    blockEach.CID = list.CID;
                    blockEach.tfileCID = list.tFileCID;
                    blockEach.hash = list.hash;
                    if(vColdBlock.find(blockEach.hash)==vColdBlock.end())
                    {
                        vColdBlock.insert(std::pair<uint256, CBlockEach>(blockEach.hash,blockEach));
                    }
                    auto newTime = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
                    csvStream << newTime << "," << list.hash.ToString() << ",2\n";
                    flag = true;
                }
            }
        }
    }

    csvStream.close();
    return flag;

    // for(auto & item : vStorageContract) {
    //     if(item.nReputation > 0) {
    //       for(auto & ipfsNode : item.vIPFSNode) {

    //       }
    //         item.vIPFSNode.front().getIP();
    //     }
    // }
}


void CBlockContractManager::receiveContract(IpfsContract& contract)
{
    LOCK(cs_main);

    LogPrintf("[recieve contract]: memory monitoring up:%d\n",getValue());
    // std::cout << "Recieve a contract~" << std::endl;
    if (vStorageContract.find(contract.getAddress()) != vStorageContract.end()) {
        std::map<uint256, StorageContract>::iterator iter = vStorageContract.find(contract.getAddress());
        // StorageContract &sContract = vStorageContract.find(contract.getAddress())->second;
        // LogPrintf("local storage size: %d, contract: %d\n", iter->second.vIPFSNode.size(), contract.theContractState.num_ipfsnode);
        // TODO: This position has core dump several times, must repair asap.
        if (contract.theContractState.num_ipfsnode > iter->second.vIPFSNode.size()) {
            for (int i = 0; i < contract.theContractState.num_ipfsnode; ++i) {
                if (iter->second.vIPFSNode.find(contract.aIpfsNode[i].address) == iter->second.vIPFSNode.end()) {
                    CIPFSNode ipfsNode;
                    ipfsNode.pubKey = contract.aIpfsNode[i].address;
                    LogPrintf("Pubkey: %s\n", ipfsNode.pubKey);
                    ipfsNode.ip = contract.aIpfsNode[i].ip;
                    iter->second.vIPFSNode.insert(std::pair<std::string, CIPFSNode>(ipfsNode.pubKey, ipfsNode));
                }
            }
        }

        if (contract.getArgs()[0] == "save_block") {
            std::fstream csvStream;
            fs::path csvPath = GetDataDir() / "upload.csv";
            csvStream.open(csvPath.string(), ios::app);
            // std::cout << "Proof started!" <<std::endl;
            ReadKey();
            if (vColdBlock.find(uint256S(contract.getArgs()[1].c_str())) != vColdBlock.end()) {
                // LogPrintf("Core dump prevent 1\n");
                std::map<uint256, CBlockEach>::iterator blockIter = vColdBlock.find(uint256S(contract.getArgs()[1].c_str()));
                ;

                // To store the proof state
                int ret = -1;
                /**
                 * @brief Check the Tfile CID in contract. If the CID is not the same
                 * Then user will seem that this save block is save from others. User
                 * will store this tfile and change the CID in vColdBlock. Before storing
                 * the file, user has to validate the tfile and proof is correctly
                 * calculated. So user have to cat both of them to calculate and compare.
                 *
                 */
                if (contract.getArgs().size() > 7) {
                    if (blockIter->second.tfileCID != contract.getArgs()[5]) {
                        CPOR_t* t = UnserializeT(StrHex(GetFromIPFS(contract.getArgs()[5])));
                        CPOR_challenge* challenge = UnserializeChallenge(StrHex(GetFromIPFS(contract.getArgs()[6])));
                        CPOR_proof* proof = UnserializeProof(StrHex(GetFromIPFS(contract.getArgs()[4])));
                        ret = cpor_verify_proof(challenge->global,
                            proof,
                            challenge,
                            t->k_prf,
                            t->alpha);
                        if (ret) {
                            fs::path tfilepath = GetDataDir() / "cpor" / "Tfiles" / contract.getAddress().ToString().append(".t");
                            if (fs::exists(tfilepath)) fs::remove(tfilepath);
                            FILE* tfile = fsbridge::fopen(tfilepath, "w");
                            write_cpor_t_without_key(t, tfile);
                            blockIter->second.tfileCID = contract.getArgs()[5];
                            fclose(tfile);
                        }
                        destroy_cpor_challenge(challenge);
                        destroy_cpor_proof(proof);
                        destroy_cpor_t(t);
                    } else {
                        ret = cpor_verify_file(blockIter->second.hash.ToString(),
                            UnserializeChallenge(StrHex(GetFromIPFS(contract.getArgs()[6]))),
                            UnserializeProof(StrHex(GetFromIPFS(contract.getArgs()[4]))),
                            pkey);
                    }
                }


                // LogPrintf("cpor_verify result: %d\n", ret);
                if (ret == 1) {
                    // std::cout << "Proof success!" <<std::endl;
                    iter->second.nReputation++;
                    removeBlock(blockIter->second.hash.ToString());
                } else {
                    // std::cout << "Proof failed!" <<std::endl;
                    iter->second.nReputation--;
                }
                auto saveTime = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
                csvStream << saveTime << "," << blockIter->second.hash.ToString() << ",3\n";
            } else {
                // LogPrintf("Core dump prevent 2\n");
                CBlockEach newBlock;
                CPOR_t* t = UnserializeT(StrHex(GetFromIPFS(contract.getArgs()[5])));
                CPOR_challenge* challenge = UnserializeChallenge(StrHex(GetFromIPFS(contract.getArgs()[6])));
                CPOR_proof* proof = UnserializeProof(StrHex(GetFromIPFS(contract.getArgs()[4])));
                int ret = cpor_verify_proof(challenge->global,
                    proof,
                    challenge,
                    t->k_prf,
                    t->alpha);
                if (ret) {
                    // TODO 0422: If user didn't push this file to smart contract but recv set push and ignore to upload
                    fs::path tfilepath = GetDataDir() / "cpor" / "Tfiles" / contract.getAddress().ToString().append(".t");
                    if (fs::exists(tfilepath)) fs::remove(tfilepath);
                    FILE* tfile = fsbridge::fopen(tfilepath, "w");
                    write_cpor_t_without_key(t, tfile);
                    fclose(tfile);
                    newBlock.tfileCID = contract.getArgs()[5];
                    newBlock.hash = uint256S(contract.getArgs()[1].c_str());
                    vColdBlock.insert(std::pair<uint256, CBlockEach>(newBlock.hash, newBlock));
                    removeBlock(newBlock.hash.ToString());
                }
                destroy_cpor_challenge(challenge);
                destroy_cpor_proof(proof);
            }

            csvStream.close();
        }
        if (contract.getArgs()[0] == "save_blocks") {
            std::fstream csvStream;
            fs::path csvPath = GetDataDir() / "upload.csv";
            csvStream.open(csvPath.string(), ios::app);
            // std::cout << "Proof started!" <<std::endl;
            ReadKey();

            for (int i = 3; i + 6 < contract.getArgs().size(); i += 7) {
                if (vColdBlock.find(uint256S(contract.getArgs()[i].c_str())) != vColdBlock.end()) {
                    // LogPrintf("Save blocks handle:%s\n", contract.getArgs()[i].c_str());
                    std::map<uint256, CBlockEach>::iterator blockIter = vColdBlock.find(uint256S(contract.getArgs()[i].c_str()));
                    ;

                    // To store the proof state
                    int ret = -1;
                    /**
                     * @brief Check the Tfile CID in contract. If the CID is not the same
                     * Then user will seem that this save block is save from others. User
                     * will store this tfile and change the CID in vColdBlock. Before storing
                     * the file, user has to validate the tfile and proof is correctly
                     * calculated. So user have to cat both of them to calculate and compare.
                     *
                     */


                    if (blockIter->second.tfileCID != contract.getArgs()[i + 3]) {
                        CPOR_t* t = UnserializeT(StrHex(GetFromIPFS(contract.getArgs()[i + 3])));
                        CPOR_challenge* challenge = UnserializeChallenge(StrHex(GetFromIPFS(contract.getArgs()[i + 4])));
                        CPOR_proof* proof = UnserializeProof(StrHex(GetFromIPFS(contract.getArgs()[i + 2])));
                        ret = cpor_verify_proof(challenge->global,
                            proof,
                            challenge,
                            t->k_prf,
                            t->alpha);
                        if (ret) {
                            // LogPrintf("The Tfile is not match... update\n");
                            fs::path tfilepath = GetDataDir() / "cpor" / "Tfiles" / contract.getAddress().ToString().append(".t");
                            if (fs::exists(tfilepath)) fs::remove(tfilepath);
                            FILE* tfile = fsbridge::fopen(tfilepath, "w");
                            write_cpor_t_without_key(t, tfile);
                            blockIter->second.tfileCID = contract.getArgs()[i + 3];
                            fclose(tfile);
                        }
                        destroy_cpor_challenge(challenge);
                        destroy_cpor_proof(proof);
                        destroy_cpor_t(t);
                    } else {
                        ret = cpor_verify_file(blockIter->second.hash.ToString(),
                            UnserializeChallenge(StrHex(GetFromIPFS(contract.getArgs()[i + 4]))),
                            UnserializeProof(StrHex(GetFromIPFS(contract.getArgs()[i + 2]))),
                            pkey);
                    }


                    // LogPrintf("cpor_verify result: %d\n", ret);
                    if (ret == 1) {
                        // std::cout << "Proof success!" <<std::endl;
                        iter->second.nReputation++;
                        removeBlock(blockIter->second.hash.ToString());
                    } else {
                        // std::cout << "Proof failed!" <<std::endl;
                        iter->second.nReputation--;
                    }
                    auto newTime = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
                    csvStream << newTime << "," << blockIter->second.hash.ToString() << ",3\n";
                }
            }


            csvStream.close();
        }


        if (contract.getArgs()[0] == "proof_block") {
            std::fstream csvStream;
            fs::path csvPath = GetDataDir() / "challenge.csv";
            csvStream.open(csvPath.string(), ios::app);
            // std::cout << "Proof Block started!" <<std::endl;
            ReadKey();
            if (vColdBlock.find(uint256S(contract.getArgs()[1].c_str())) != vColdBlock.end()) {
                CBlockEach coldblock = vColdBlock.find(uint256S(contract.getArgs()[1].c_str()))->second;
                // To store the proof state
                int ret = -1;
                /**
                 * @brief Check the Tfile CID in contract. If the CID is not the same
                 * Then user will seem that this save block is save from others. User
                 * will store this tfile and change the CID in vColdBlock. Before storing
                 * the file, user has to validate the tfile and proof is correctly
                 * calculated. So user have to cat both of them to calculate and compare.
                 *
                 */
                auto proofTimeStart = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
                csvStream << proofTimeStart << "," << coldblock.hash.ToString() << ",1";
                ret = cpor_verify_file(coldblock.hash.ToString(),
                    UnserializeChallenge(StrHex(GetFromIPFS(contract.getArgs()[4]))),
                    UnserializeProof(StrHex(GetFromIPFS(contract.getArgs()[3]))),
                    pkey);


                // LogPrintf("cpor_verify result: %d\n", ret);
                if (ret == 1) {
                    // std::cout << "Proof success!" <<std::endl;
                    iter->second.nReputation++;
                } else {
                    // std::cout << "Proof failed!" <<std::endl;
                    iter->second.nReputation--;
                }
                auto proofTimeEnd = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
                csvStream << proofTimeEnd << "," << coldblock.hash.ToString() << ",2";
            }
            csvStream.close();
        }
    } else {
        StorageContract newS;
        for (int i = 0; i < contract.theContractState.num_ipfsnode; ++i) {
            CIPFSNode ipfsNode;
            ipfsNode.pubKey = contract.aIpfsNode[i].address;
            LogPrintf("Pubkey: %s\n", ipfsNode.pubKey);
            ipfsNode.ip = contract.aIpfsNode[i].ip;
            newS.vIPFSNode.insert(std::pair<std::string, CIPFSNode>(ipfsNode.pubKey, ipfsNode));
        }
        LogPrintf("Insert new contract\n");
        newS.hash = contract.getAddress();
        vStorageContract.insert(std::pair<uint256, StorageContract>(newS.hash, newS));
    }
    LogPrintf("[recieve contract]: memory monitoring down:%d\n",getValue());

}
CBlock* CBlockContractManager::retrieveBlock(uint256)
{
    return nullptr;
}


void CBlockContractManager::InitParams()
{
    // No longer need
}

int CBlockContractManager::InitKey()
{
    CPOR_key* key = NULL;
    FILE* keyfile = NULL;
    size_t Zp_size = 0;
    unsigned char* Zp = NULL;

    fs::path path = GetDataDir() / "cpor";
    fs::create_directory(path);
    path /= "cpor.key";
    // LogPrintf("Get the path\n");

    if (fs::exists(path)) return ReadKey();

    // LogPrintf("Get the new CPOR key\n");
    if (((key = allocate_cpor_key(cParams.enc_key_size, cParams.mac_key_size)) == nullptr)) return -1;
    if (((key->global = cpor_create_global(cParams.Zp_bits)) == NULL)) return -1;
    // LogPrintf("Allocate success\n");
    if (!RAND_bytes(key->k_enc, cParams.enc_key_size)) return -1;
    key->k_enc_size = cParams.enc_key_size;
    if (!RAND_bytes(key->k_mac, cParams.mac_key_size)) return -1;
    key->k_mac_size = cParams.mac_key_size;

    // LogPrintf("Open CPOR key path\n");
    pkey = key;
    keyfile = fsbridge::fopen(path, "w");
    if (!keyfile) return -1;
    // LogPrintf("CPOR key open complete\n");
    fwrite(&key->k_enc_size, sizeof(size_t), 1, keyfile);
    if (ferror(keyfile)) return -1;
    fwrite(key->k_enc, key->k_enc_size, 1, keyfile);
    if (ferror(keyfile)) return -1;
    fwrite(&key->k_mac_size, sizeof(size_t), 1, keyfile);
    if (ferror(keyfile)) return -1;
    fwrite(key->k_mac, key->k_mac_size, 1, keyfile);
    if (ferror(keyfile)) return -1;
    // LogPrintf("Zp\n");

    Zp_size = BN_num_bytes(key->global->Zp);
    fwrite(&Zp_size, sizeof(size_t), 1, keyfile);
    Zp = new unsigned char[Zp_size];
    // if (((Zp = (unsigned char *)malloc(Zp_size)) == NULL)) return -1;
    memset(Zp, 0, Zp_size);
    if (!BN_bn2bin(key->global->Zp, Zp)) return -1;
    fwrite(Zp, Zp_size, 1, keyfile);
    // LogPrintf("keyfile and zp free\n");
    if (keyfile) fclose(keyfile);
    if (Zp) sfree(Zp, Zp_size);
    // LogPrintf("key complete\n");


    return 1;
}

int CBlockContractManager::ReadKey()
{
    CPOR_key* key = NULL;
    FILE* keyfile = NULL;
    size_t Zp_size = 0;
    unsigned char* Zp = NULL;
    fs::path path = GetDataDir() / "cpor";
    fs::create_directory(path);
    path /= "cpor.key";
    if (((key = allocate_cpor_key(cParams.enc_key_size, cParams.mac_key_size)) == nullptr)) return -1;
    if (((key->global = allocate_cpor_global()) == NULL)) return -1;
    // LogPrintf("RdKey:Open CPOR key path\n");
    // LogPrintf("CPOR key path: %s\n", path.c_str());
    keyfile = fsbridge::fopen(path, "r");
    if (!keyfile) return InitKey();
    // LogPrintf("RdKey:Read CPOR key\n");

    fread(&(key->k_enc_size), sizeof(size_t), 1, keyfile);
    if (ferror(keyfile)) return -1;
    fread(key->k_enc, key->k_enc_size, 1, keyfile);
    if (ferror(keyfile)) return -1;
    fread(&(key->k_mac_size), sizeof(size_t), 1, keyfile);
    if (ferror(keyfile)) return -1;
    fread(key->k_mac, key->k_mac_size, 1, keyfile);
    if (ferror(keyfile)) return -1;

    fread(&Zp_size, sizeof(size_t), 1, keyfile);
    if (ferror(keyfile)) return -1;
    if (((Zp = (unsigned char*)malloc(Zp_size)) == NULL)) return -1;
    memset(Zp, 0, Zp_size);
    fread(Zp, Zp_size, 1, keyfile);
    if (ferror(keyfile)) return -1;
    if (!BN_bin2bn(Zp, Zp_size, key->global->Zp)) return -1;
    // LogPrintf("RdKey:cmp\n");

    if (Zp) sfree(Zp, Zp_size);
    if (keyfile) fclose(keyfile);
    pkey = key;
    // free(key);

    return 1;
}

void CBlockContractManager::challengeBlock(int nHeight)
{
    LOCK(cs_main);
    if (vStorageContract.size() == 0) return;
    LogPrintf("[challengeBlock]: memory monitoring up:%d\n",getValue());

    int nChallengeTime = gArgs.GetArg("-challengetimes",CHALLENGE_TIME);
    if (nHeight > n_last_challenge_height + nChallengeTime) {
        srand(time(NULL));
        std::cout << "Challenge..." << std::endl;
        // TODO: check TFILECID vs blockCID
        fs::path csvPath = GetDataDir() / "challenge.csv";
        std::fstream csvStream;
        csvStream.open(csvPath.string(), ios::app);
        ChallengeMessage chalmsg;
        std::map<std::string, NodeId> nodes;
        getNodeStat(nodes);
        ReadKey();
        for (auto& Itemcontract : vStorageContract) {
            if (Itemcontract.second.vIPFSNode.size() != 0) {
                Contract ccontract;
                ccontract.address = Itemcontract.second.hash;
                IpfsContract ipfscontract(ccontract);

                LogPrintf("IPFS contract num_ipfsnode:%d\n", ipfscontract.theContractState.num_ipfsnode);
                int nChallengeblocks = gArgs.GetArg("-challengeblocks",CHALLENGE_BLOCKS);
                std::vector<uint256> blocks;
                for (auto& ipfs : Itemcontract.second.vIPFSNode) {
                    blocks = ipfscontract.getSavedBlock(ipfs.second.pubKey);
                    LogPrintf("Output blocks size: %d\n", blocks.size());
                    if (blocks.size() == 0){
                        blocks.clear();
                        continue;
                    } 

                    
                    int rand_times = blocks.size() > nChallengeblocks ? nChallengeblocks : blocks.size();
                    Block* block = nullptr;
                    for (int i = 0; i < rand_times; ++i) {
                        LogPrintf("Challenge times:%d\n", i);
                        int rand_num = rand() % blocks.size();
                        block = ipfscontract.findBlock(blocks[rand_num].ToString());
                        CPOR_challenge* pchallenge;
                        LogPrintf("TFILECID: %s\n",block->tfileCID);
                        if(block == nullptr) continue;
                        // if(block.tfileCID != vColdBlock.find(blocks[rand_num])->second.tfileCID){
                        CPOR_t* t = UnserializeT(StrHex(GetFromIPFS(block->tfileCID)));
                        pchallenge = cpor_create_challenge(pkey->global, t->n);
                        destroy_cpor_t(t);
                        // } else {
                        //     pchallenge = cpor_challenge_file(blocks[rand_num].ToString(), pkey);
                        // }
                        LogPrintf("Challenge create\n");
                        if (!pchallenge) continue;
                        std::vector<unsigned char> challenge = SerializeChallenge(pchallenge);
                        destroy_cpor_challenge(pchallenge);
                        std::string challengeCID = AddToIPFS(HexStr(challenge));
                        LogPrintf("Output challenge: %s\n", challengeCID);
                        chalmsg.vChallenge.push_back(std::pair<uint256, std::string>(blocks[rand_num], challengeCID));
                        csvStream << time(NULL) << "," << blocks[rand_num].ToString() << ",0\n";

                    }
                    NodeId nodeid = nodes.find(ipfs.second.getIP())->second;
                    g_connman->ForNodeMsg(nodeid, chalmsg);
                }
                // ipfscontract.~IpfsContract();
            }
        }
        csvStream.close();
        n_last_challenge_height = nHeight;
    }
    LogPrintf("[challengeBlock]: memory monitoring end:%d\n",getValue());

}