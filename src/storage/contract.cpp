
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

#define COLDPOOL_MAX 10
#define WORKINGSET_SIZE 32
#define CHALLENGE_TIME 10
#define CHALLENGE_BLOCKS 10


void CBlockContractManager::appendColdPool(std::pair<uint256, FlatFilePos> pair)
{
    LOCK(cs_main);
    if (vColdPool.size() > COLDPOOL_MAX) {
        std::vector<CBlockEach> vDeployList;
        fs::path csvPath = GetDataDir() / "upload.csv";
        std::fstream csvStream;
        csvStream.open(csvPath.string(), ios::app);

        ReadKey();

        // LogPrintf("Pkey info: k_enc: %s\n",pkey->k_enc);
        for (auto& item : vColdPool) {
            csvStream << time(NULL) << "," << item.first.ToString() << ",0\n";
            CBlock block;
            fs::path newBlockPath = GetBlocksDir() / strprintf("blk_%s.dat", item.first.ToString());
            FlatFilePos pos(item.second);
            FILE* f = fsbridge::fopen(newBlockPath, "rb");
            fseek(f, pos.nPos, SEEK_SET);
            CAutoFile filein(f, SER_DISK, CLIENT_VERSION);

            try {
                filein >> block;
            } catch (const std::exception& e) {
                return;
            }


            // CBLOCK SERIALIZE
            json::value root;
            CppRestConstructBlockToJson(block, root);
            std::string str = root.serialize();

            // //CPOR tag


            fs::path path = GetDataDir() / "cpor";
            fs::create_directory(path);
            fs::path TagFile = path / "Tags" / item.first.ToString().append(".tag");
            fs::path TFile = path / "Tfiles" / item.first.ToString().append(".t");
            if (fs::exists(TFile)) continue;
            local_cpor_tag_file(str, item.first, pkey);
            csvStream << time(NULL) << "," << item.first.ToString() << ",1\n";
            std::vector<unsigned char> t_bin = readFileToUnsignedChar(TFile.string());
            // mTagFile.insert(pair<uint256, FILE*>(item.GetHash(),fsbridge::fopen(path,"r")));
            std::vector<unsigned char> challenge = SerializeChallenge(cpor_challenge_file(item.first.ToString(), pkey));
            // std::cout <<"Challenge" << HexStr(challenge) <<std::endl;
            // Push To IPFS & get CID back
            CBlockEach cBlockEach{};

            cBlockEach.CID = AddToIPFS(str);
            cBlockEach.TagCID = AddToIPFS(HexStr(readFileToUnsignedChar(TagFile.string())));
            cBlockEach.firstChallengeCID = AddToIPFS(HexStr(challenge));
            cBlockEach.tfileCID = AddToIPFS(HexStr(t_bin));
            cBlockEach.hash = item.first;
            vDeployList.push_back(cBlockEach);
        }

        // Find Contract To deploy
        // If yes:
        std::cout << "deploy" << std::endl;
        if (deployContract(vDeployList)) {
            vColdPool.clear();
        }


        csvStream.close();
        // vColdPool.clear();
    }
    vColdPool.push_back(pair);
}

void CBlockContractManager::workingSet(uint256 hash, FlatFilePos pos)
{
    // std::cout << "workingset size:" << vWorkingSet.size() <<std::endl;
    for (auto it = vWorkingSet.begin(); it != vWorkingSet.end(); ++it) {
        if (it->first == hash) {
            vWorkingSet.insert(vWorkingSet.begin(), *it);
            vWorkingSet.erase(it);
            return;
        }
    }
    if ((vWorkingSet.size() + 1) > WORKINGSET_SIZE) {
        appendColdPool(std::pair<uint256, FlatFilePos>(vWorkingSet.back().first, vWorkingSet.back().second));
        vWorkingSet.pop_back();
    }
    vWorkingSet.push_back(std::pair<uint256, FlatFilePos>(hash, pos));
}

bool CBlockContractManager::lookupWorkingSet(FlatFilePos pos)
{
    for (auto& it : vWorkingSet) {
        if (pos.hash == it.first) {
            return true;
        }
    }
    return false;
}

bool CBlockContractManager::lookupColdPool(FlatFilePos pos)
{
    for (auto& it : vColdPool) {
        if (pos.hash == it.first) {
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
    if(vColdBlock.find(pos.hash)!=vColdBlock.end()) {
      GetBlockFromIPFS(block, vColdBlock.find(pos.hash)->second.CID);
    }
}

// This function is used to parse node stats to map in local
static void getNodeStat(std::map<std::string, NodeId>& nodes)
{
    std::vector<CNodeStats> nodeStats;
    g_connman->GetNodeStats(nodeStats);
    for (auto& node : nodeStats) {
        nodes.insert(std::pair<std::string, NodeId>(node.addr.ToStringIPPort(), node.nodeid));
    }
}

bool CBlockContractManager::deployContract(std::vector<CBlockEach>& vDeployList)
{
    LOCK(cs_main);
    sort(vStorageContract.begin(), vStorageContract.end(), [](StorageContract& x, StorageContract& y) { return x.nReputation > y.nReputation; });
    std::fstream csvStream;
    fs::path csvPath = GetDataDir() / "upload.csv";
    csvStream.open(csvPath.string(), ios::app);
    // Test first contract ipfsvector


    std::cout << "Contract Size: " << vStorageContract.size() << std::endl;
    if (vStorageContract.size() == 0) return false;

    std::map<std::string, NodeId> nodes;
    getNodeStat(nodes);
    bool flag = false;

    //Check if there is a block inside coldblock then do not deploy again
    for(auto &block: vDeployList) {
      if(vColdBlock.find(block.hash)!= vColdBlock.end()) {
        vDeployList.erase();//TODO: erase if exist in vcoldblock
      }
    }

    for (auto& Itemcontract : vStorageContract) {
        if (Itemcontract.second.vIPFSNode.size() != 0) {
            for (auto& node : Itemcontract.second.vIPFSNode) {
                // CNode newNode()
                // std::cout << "discontruct ipfsnode vector" <<std::endl;
                CAddress addrConnect;

                if (nodes.find(node.second.ip) == nodes.end()) {
                    g_connman->AddNode(node.second.ip);
                    getNodeStat(nodes);
                }
                NodeId nodeid = nodes.find(node.second.ip)->second;
                // LogPrintf("Node IP: %s, node id: %d\n", node.second.ip, nodeid);
                std::vector<CStorageMessage> vMessage;
                for (auto& list : vDeployList) {
                    CStorageMessage message;
                    message.hash = list.hash;
                    message.CID = list.CID;
                    message.TagCID = list.TagCID;
                    message.firstChallengeCID = list.firstChallengeCID;
                    message.tFileCID = list.tfileCID;
                    g_connman->ForNodeMsg(nodeid, message);
                    csvStream << time(NULL) << "," << list.hash.ToString() << ",2\n";
                }
                flag = true;
            }
        }
    }
    if (flag) {
      for(auto& block : vDeployList) {
        vColdBlock.insert(std::pair<uint256, CBlockEach>(block.hash, block));
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
void CBlockContractManager::receiveContract(IpfsContract contract)
{
    LOCK(cs_main);

    // std::cout << "Recieve a contract~" << std::endl;
    if (vStorageContract.find(contract.getAddress()) != vStorageContract.end()) {
        StorageContract sContract = vStorageContract.find(contract.getAddress())->second;
        if (contract.theContractState.num_ipfsnode != sContract.vIPFSNode.size()) {
            for (int i = 0; i < contract.theContractState.num_ipfsnode; ++i) {
                if (sContract.vIPFSNode.find(contract.aIpfsNode[i].address) == sContract.vIPFSNode.end()) {
                    CIPFSNode ipfsNode;
                    ipfsNode.pubKey = contract.aIpfsNode[i].address;
                    LogPrintf("Pubkey: %s\n", ipfsNode.pubKey);
                    ipfsNode.ip = contract.aIpfsNode[i].ip;
                    sContract.vIPFSNode.insert(std::pair<std::string, CIPFSNode>(ipfsNode.pubKey, ipfsNode));
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
                if (coldblock.tfileCID != contract.getArgs()[5]) {
                    CPOR_t* t = UnserializeT(StrHex(GetFromIPFS(contract.getArgs()[5])));
                    CPOR_challenge* challenge = UnserializeChallenge(StrHex(GetFromIPFS(contract.getArgs()[6])));
                    CPOR_proof* proof = UnserializeProof(StrHex(GetFromIPFS(contract.getArgs()[4])));
                    ret = cpor_verify_proof(challenge->global,
                        proof,
                        challenge,
                        t->k_prf,
                        t->alpha);
                    if (ret) {
                        fs::path tfilepath = GetDataDir() / "cpor" / contract.getAddress().ToString().append(".t");
                        FILE* tfile = fsbridge::fopen(tfilepath, "w");
                        write_cpor_t_without_key(t, tfile);
                        coldblock.tfileCID = contract.getArgs()[5];
                    }
                } else {
                    ret = cpor_verify_file(coldblock.hash.ToString(),
                        UnserializeChallenge(StrHex(GetFromIPFS(contract.getArgs()[6]))),
                        UnserializeProof(StrHex(GetFromIPFS(contract.getArgs()[4]))),
                        pkey);
                }


                // LogPrintf("cpor_verify result: %d\n", ret);
                if (ret == 1) {
                    // std::cout << "Proof success!" <<std::endl;
                    sContract.nReputation++;
                } else {
                    // std::cout << "Proof failed!" <<std::endl;
                    sContract.nReputation--;
                }
                csvStream << time(NULL) << "," << coldblock.hash.ToString() << ",3\n";
            } else {
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
                    fs::path tfilepath = GetDataDir() / "cpor" / contract.getAddress().ToString().append(".t");
                    FILE* tfile = fsbridge::fopen(tfilepath, "w");
                    write_cpor_t_without_key(t, tfile);
                    newBlock.tfileCID = contract.getArgs()[5];
                    newBlock.hash = uint256S(contract.getArgs()[1].c_str());
                    vColdBlock.insert(std::pair<uint256, CBlockEach>(newBlock.hash, newBlock));
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

                ret = cpor_verify_file(coldblock.hash.ToString(),
                    UnserializeChallenge(StrHex(GetFromIPFS(contract.getArgs()[4]))),
                    UnserializeProof(StrHex(GetFromIPFS(contract.getArgs()[3]))),
                    pkey);


                // LogPrintf("cpor_verify result: %d\n", ret);
                if (ret == 1) {
                    // std::cout << "Proof success!" <<std::endl;
                    sContract.nReputation++;
                } else {
                    // std::cout << "Proof failed!" <<std::endl;
                    sContract.nReputation--;
                }
                csvStream << time(NULL) << "," << coldblock.hash.ToString() << ",1";
            }
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
        newS.hash = contract.getAddress();
        vStorageContract.insert(std::pair<uint256, StorageContract>(newS.hash, newS));
    }
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

    if (nHeight > n_last_challenge_height + CHALLENGE_TIME) {
        srand(time(NULL));
        std::cout << "Challenge..." << std::endl;
        fs::path csvPath = GetDataDir() / "upload.csv";
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
                ipfscontract.init();

                LogPrintf("IPFS contract num_ipfsnode:%d\n", ipfscontract.theContractState.num_ipfsnode);
                for (auto& ipfs : Itemcontract.second.vIPFSNode) {
                    std::vector<uint256> blocks = ipfscontract.getSavedBlock(ipfs.second.pubKey);
                    LogPrintf("Output blocks size: %d\n", blocks.size());
                    if (blocks.size() == 0) break;

                    int rand_times = blocks.size() > CHALLENGE_BLOCKS ? CHALLENGE_BLOCKS : blocks.size();
                    for (int i = 0; i < rand_times; ++i) {
                        int rand_num = rand() % blocks.size();
                        std::vector<unsigned char> challenge = SerializeChallenge(cpor_challenge_file(blocks[rand_num].ToString(), pkey));

                        std::string challengeCID = AddToIPFS(HexStr(challenge));
                        LogPrintf("Output challenge: %s\n", challengeCID);
                        chalmsg.vChallenge.push_back(std::pair<uint256, std::string>(blocks[rand_num], challengeCID));
                        csvStream << time(NULL) << "," << blocks[rand_num].ToString() << ",0\n";
                    }
                    NodeId nodeid = nodes.find(ipfs.second.getIP())->second;
                    g_connman->ForNodeMsg(nodeid, chalmsg);
                }
            }
        }
        n_last_challenge_height = nHeight;
    }
}