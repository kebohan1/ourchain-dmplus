
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

#include <netmessagemaker.h>
#include <netbase.h>
#include <net.h>
#include <storage/ipfs_interface.h>

using namespace std;

#define COLDPOOL_MAX 1
#define WORKINGSET_SIZE 10*sizeof(CBlock)

// TODO: select ipfs amount should be global setting
int ipfs_max_select = 4;

int ipfs_no_reputation_rate = 0.25;



void CBlockContractManager::appendColdPool(int nHeight,const CBlock pblock)
{
    LOCK(cs_main);
    if (vColdPool.size() > COLDPOOL_MAX) {
        std::vector<std::string> vSerializeColdPool;
        std::map<uint256, FILE*> mTagFile;
        std::vector<CBlockEach> vDeployList;

        ReadKey();

        // LogPrintf("Pkey info: k_enc: %s\n",pkey->k_enc);
        for (auto& item : vColdPool) {

            // CBLOCK SERIALIZE
            json::value root;
            CppRestConstructBlockToJson(item.second, root);
            std::string str = root.serialize();
            vSerializeColdPool.push_back(root.serialize());

            // //CPOR tag
            

            fs::path path = GetDataDir() / "cpor" ;
            fs::create_directory(path);
            path /= "Tags";
            path /=  item.second.GetHash().ToString().append(".tag");
            if(fs::exists(path)) continue;
            local_cpor_tag_file(str, item.second.GetHash(), pkey);

            // mTagFile.insert(pair<uint256, FILE*>(item.second.GetHash(),fsbridge::fopen(path,"r")));
            std::vector<unsigned char> challenge = SerializeChallenge(cpor_challenge_file(item.second.GetHash().ToString(),pkey));
            // std::cout <<"Challenge" << HexStr(challenge) <<std::endl;
            //Push To IPFS & get CID back
            CBlockEach cBlockEach{};
            
            cBlockEach.CID = AddToIPFS(str);
            cBlockEach.TagCID = AddToIPFS(HexStr(readFileToUnsignedChar(path.string())));
            cBlockEach.firstChallengeCID = AddToIPFS(HexStr(challenge));
            cBlockEach.hash = item.second.GetHash();
            cBlockEach.nHeight = item.first;
            vDeployList.push_back(cBlockEach);

            
        }

        // Find Contract To deploy
        // If yes:
        std::cout << "deploy" <<std::endl;
        if(deployContract(vDeployList)) vColdPool.clear();

        // vColdPool.clear();
        

    }
    vColdPool.push_back(std::pair<int,CBlock>(nHeight,pblock));
}

void CBlockContractManager::workingSet(int nHeight,CBlock* block){
  std::cout << "workingset size:" << vWorkingSet.size() <<std::endl;
  for(auto it = vWorkingSet.begin();it != vWorkingSet.end(); ++it){
    if(it->second.GetHash() == block->GetHash()) {
      vWorkingSet.insert(vWorkingSet.begin(),*it);
      vWorkingSet.erase(it);
      return;
    }
  }
  if((vWorkingSet.size() + 1) * sizeof(*block) > WORKINGSET_SIZE) {
    appendColdPool(vWorkingSet.back().first,vWorkingSet.back().second);
    vWorkingSet.pop_back();
  }
  vWorkingSet.push_back(std::pair<int,CBlock>(nHeight,*block));
}

CBlock CBlockContractManager::lookupWorkingSet(CBlock* block, FlatFilePos pos) {
  CBlock nullBlock;
  for(auto it = vWorkingSet.begin();it != vWorkingSet.end(); ++it){
    // if(it->first.nFile == pos.nFile && it->first.nPos == pos.nPos) {
    //   return *(it->second);
    // }
  }
  return nullBlock;
}

std::string CBlockContractManager::lookupColdBlock(FlatFilePos pos) {
  for(auto &it : vColdBlock) {
    // if(pos.nFile == it.filepos.nFile && pos.nPos == it.filepos.nPos) {
    //   return it.CID;
    // }
  }
  return NULL;
}

void CBlockContractManager::hotColdClassifier(CBlock* block) {

}

//This function is used to parse node stats to map in local
static void getNodeStat(std::map<std::string, NodeId>& nodes) {
  std::vector<CNodeStats>nodeStats;
  g_connman->GetNodeStats(nodeStats);
  for(auto &node: nodeStats){
    nodes.insert(std::pair<std::string, NodeId>(node.addr.ToStringIPPort(),node.nodeid));
  }
}

bool CBlockContractManager::deployContract(std::vector<CBlockEach> &vDeployList) {


    sort(vStorageContract.begin(), vStorageContract.end(), [] (StorageContract &x, StorageContract &y) { return x.nReputation > y.nReputation; });

    //Test first contract ipfsvector
    std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
    std::shared_ptr<CWallet> const wallet = wallets.size() == 1 || wallets.size() > 0 ? wallets[0] : nullptr;

    CWallet* const pwallet = wallet.get();
    CPubKey newKey;

    pwallet->GetKeyFromPool(newKey);
    
    std::cout << "Contract Size: " << vStorageContract.size() << std::endl;
    if(vStorageContract.size() == 0) return false;

    std::map<std::string, NodeId> nodes;
    getNodeStat(nodes);
    for(auto &Itemcontract : vStorageContract) {
      if(Itemcontract.vIPFSNode.size()!=0) {
        for(auto &node:Itemcontract.vIPFSNode){
          // CNode newNode()
          // std::cout << "discontruct ipfsnode vector" <<std::endl;
          CAddress addrConnect;

          if(nodes.find(node.second.ip) == nodes.end()) {
            g_connman->AddNode(node.second.ip);
            getNodeStat(nodes);

          }
          NodeId nodeid = nodes.find(node.second.ip)->second;
          LogPrintf("Node IP: %s, node id: %d\n",node.second.ip, nodeid);
          std::vector<CStorageMessage> vMessage;
          for(auto & list: vDeployList) {
            CStorageMessage message;
            message.hash = list.hash;
            message.CID = list.CID;
            message.TagCID = list.TagCID;
            message.firstChallengeCID = list.firstChallengeCID;
            g_connman->ForNodeMsg(nodeid, message);
          }
        }
      }
    }
    vColdBlock.insert(vColdBlock.end(),vDeployList.begin(),vDeployList.end());

    return true;
    
    // for(auto & item : vStorageContract) {
    //     if(item.nReputation > 0) {
    //       for(auto & ipfsNode : item.vIPFSNode) {

    //       }
    //         item.vIPFSNode.front().getIP();
    //     }
    // }
}
void CBlockContractManager::receiveContract(IpfsContract contract) {
  LOCK(cs_main);
  StorageContract s;
  std::cout << "Recieve a contract~" << std::endl;
  for(auto& item: vStorageContract) {
    std::cout << "Contract Addr: " << contract.getAddress().ToString()<< std::endl;
    if(item.hash == contract.getAddress()) {
      std::cout << "Contract exist! just append nodes" <<std::endl;
      //check new ipfsnode sign_up
      for(int i = 0; i< contract.theContractState.num_ipfsnode; ++i) { 
        if(item.vIPFSNode.find(uint256S(contract.aIpfsNode[i].address))== item.vIPFSNode.end()) {
          CIPFSNode ipfsNode;
          ipfsNode.pubKey = uint256S(contract.aIpfsNode[i].address);
          ipfsNode.ip = contract.aIpfsNode[i].ip ;
          item.vIPFSNode.insert(std::pair<uint256, CIPFSNode>(ipfsNode.pubKey,ipfsNode));
        }
      }
      
      if(contract.getArgs()[0] == "save_block" && contract.getArgs().size() == 7) {
        std::cout << "Proof started!" <<std::endl;
        ReadKey();
        for(auto& coldblock : vColdBlock){
          //TODO: 0419 following if is not jump in
          
          if(coldblock.hash.ToString() == contract.getArgs()[1]) {
            std::cout << "Source merkle: " << coldblock.hash.ToString() << ",Output merkle:" << contract.getArgs()[1] <<std::endl;
            int ret = cpor_verify_file(coldblock.hash.ToString(),
                                      UnserializeChallenge(StrHex(GetFromIPFS(contract.getArgs()[6]))),
                                      UnserializeProof(StrHex(GetFromIPFS(contract.getArgs()[4]))),
                                      pkey);
            LogPrintf("cpor_verify result: %d\n", ret);
            if(ret == 1) {
              std::cout << "Proof success!" <<std::endl;
              item.nReputation++;
            } else {
              std::cout << "Proof failed!" <<std::endl;
              item.nReputation--;
            }
          }
        }
        
      }

      //check proof
      // for(int i = 0; i< contract.theContractState.num_blocks; ++i) {
      //   if()
      // }
      return;
    } 
  }
  for(int i = 0; i < contract.theContractState.num_ipfsnode; ++i) {
        s.hash = contract.getAddress();
        CIPFSNode ipfsNode;
          ipfsNode.pubKey = uint256S(contract.aIpfsNode[i].address);
          ipfsNode.ip = contract.aIpfsNode[i].ip;
          s.vIPFSNode.insert(std::pair<uint256, CIPFSNode>(ipfsNode.pubKey,ipfsNode));
      }
  vStorageContract.push_back(s);
}
CBlock* CBlockContractManager::retrieveBlock(uint256) {
  return nullptr;
}



void CBlockContractManager::InitParams()
{
  //No longer need
}

int CBlockContractManager::InitKey()
{
    CPOR_key* key = NULL;
    FILE* keyfile = NULL;
    size_t Zp_size = 0;
    unsigned char* Zp = NULL;

    fs::path path = GetDataDir() / "cpor" ;
  fs::create_directory(path);
  path /= "cpor.key";
    LogPrintf("Get the path\n");

    if(fs::exists(path)) return ReadKey();

    LogPrintf("Get the new CPOR key\n");
    if (((key = allocate_cpor_key(cParams.enc_key_size,cParams.mac_key_size)) == nullptr)) return -1;
    if (((key->global = cpor_create_global(cParams.Zp_bits)) == NULL)) return -1;
    LogPrintf("Allocate success\n");
    if (!RAND_bytes(key->k_enc, cParams.enc_key_size)) return -1;
    key->k_enc_size = cParams.enc_key_size;
    if (!RAND_bytes(key->k_mac, cParams.mac_key_size)) return -1;
    key->k_mac_size = cParams.mac_key_size;
    
    LogPrintf("Open CPOR key path\n");
    pkey = key;
    keyfile = fsbridge::fopen(path, "w");
    if (!keyfile) return -1;
    LogPrintf("CPOR key open complete\n");
    fwrite(&key->k_enc_size, sizeof(size_t), 1, keyfile);
    if (ferror(keyfile)) return -1;
    fwrite(key->k_enc, key->k_enc_size, 1, keyfile);
    if (ferror(keyfile)) return -1;
    fwrite(&key->k_mac_size, sizeof(size_t), 1, keyfile);
    if (ferror(keyfile)) return -1;
    fwrite(key->k_mac, key->k_mac_size, 1, keyfile);
    if (ferror(keyfile)) return -1;
    LogPrintf("Zp\n");

    Zp_size = BN_num_bytes(key->global->Zp);
    fwrite(&Zp_size, sizeof(size_t), 1, keyfile);
    Zp = new unsigned char[Zp_size];
    // if (((Zp = (unsigned char *)malloc(Zp_size)) == NULL)) return -1;
    memset(Zp, 0, Zp_size);
    if (!BN_bn2bin(key->global->Zp, Zp)) return -1;
    fwrite(Zp, Zp_size, 1, keyfile);
    LogPrintf("keyfile and zp free\n");
    if (keyfile) fclose(keyfile);
    if (Zp) sfree(Zp, Zp_size);
    LogPrintf("key complete\n");


    return 1;
}

int CBlockContractManager::ReadKey() {


	CPOR_key *key = NULL;
	FILE *keyfile = NULL;
	size_t Zp_size = 0;
	unsigned char *Zp = NULL;
  fs::path path = GetDataDir() / "cpor" ;
  fs::create_directory(path);
  path /= "cpor.key";
	if( ((key = allocate_cpor_key(cParams.enc_key_size,cParams.mac_key_size)) == nullptr)) return -1;
	if( ((key->global = allocate_cpor_global()) == NULL)) return -1;
    LogPrintf("RdKey:Open CPOR key path\n");
  LogPrintf("CPOR key path: %s\n", path.c_str());
	keyfile = fsbridge::fopen(path, "r");
  if (!keyfile) return InitKey();
    LogPrintf("RdKey:Read CPOR key\n");
	
	fread(&(key->k_enc_size), sizeof(size_t), 1, keyfile);
	if(ferror(keyfile)) return -1;
	fread(key->k_enc, key->k_enc_size, 1, keyfile);
	if(ferror(keyfile)) return -1;
	fread(&(key->k_mac_size), sizeof(size_t), 1, keyfile);
	if(ferror(keyfile)) return -1;
	fread(key->k_mac, key->k_mac_size, 1, keyfile);
	if(ferror(keyfile)) return -1;

	fread(&Zp_size, sizeof(size_t), 1, keyfile);
	if(ferror(keyfile)) return -1;
	if( ((Zp = (unsigned char *)malloc(Zp_size)) == NULL)) return -1;
	memset(Zp, 0, Zp_size);
	fread(Zp, Zp_size, 1, keyfile);
	if(ferror(keyfile)) return -1;
	if(!BN_bin2bn(Zp, Zp_size, key->global->Zp)) return -1;
    LogPrintf("RdKey:cmp\n");
	
	if(Zp) sfree(Zp, Zp_size);
	if(keyfile) fclose(keyfile);
  pkey = key;
  // free(key);
	
	return 1;
}

uint256 deploySysContract(CBlock& pblock)
{
    // TODO: check amount of wallet
    std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
    std::shared_ptr<CWallet> const wallet = wallets.size() == 1 || wallets.size() > 0 ? wallets[0] : nullptr;

    if (wallet == nullptr) {
        fprintf(stderr, "Wallet is empty, create first.\n");
        return uint256S("0");
    }
    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet); // prevent insufficient funds

    Contract contract;

    ReadFile("./ipfsContract.c", contract.code);

    contract.action = contract_action::ACTION_NEW;
    contract.usage = contract_usage::USAGE_SYS;

    contract.address = uint256();

    if (!pwallet->IsLocked())
        pwallet->TopUpKeyPool();
    // Generate a new key that is added to wallet
    CPubKey newKey;

    if (!pwallet->GetKeyFromPool(newKey)) {
        fprintf(stderr, "Error: Keypool ran out, please call keypoolrefill first");
        return uint256S("0");
    }


    CKeyID keyID = newKey.GetID();
    OutputType output_type = pwallet->m_default_change_type != OutputType::CHANGE_AUTO ? pwallet->m_default_change_type : pwallet->m_default_address_type;
    CTxDestination dest = GetDestinationForKey(newKey, output_type);

    std::string strAccount;
    pwallet->SetAddressBook(dest, strAccount, "receive");

    // sendtoaddress

    //  CBitcoinAddress address(CBitcoinAddress(keyID).ToString());
    if (!IsValidDestination(dest)) {
        fprintf(stderr, "Invalid Bitcoin address");
        return uint256S("0");
    }

    if (pwallet->IsLocked()) {
        fprintf(stderr, "Error: Please enter the wallet passphrase with walletpassphrase first.");
        return uint256S("0");
    }

    //  CWalletTx wtx;
    CTransactionRef tx;
    CCoinControl no_coin_control;
    SendContractTx(pwallet, &contract, dest, tx, no_coin_control);

    //

    return contract.address;
}

std::string openLevelDB(std::string path, std::string key)
{
    leveldb::DB* db;
    leveldb::Options option;
    option.create_if_missing = false;
    leveldb::DB::Open(option, path, &db);
    leveldb::DB::Open(option, path, &db);
    std::string result;
    leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &result);

    delete db;
    if (status.IsNotFound() == true) return "";
    return result;
}

bool checkContractOwner(std::string sContractHash)
{
    fs::path path = GetDataDir() / "Storage/Contract";
    std::string sContractStatus = openLevelDB(path.c_str(), sContractHash);

    // if no data found or the status of contract is end, return false
    if (sContractHash == "" || (sContractHash != "" && sContractStatus == "-1")) return false;
    return true;
}

// CIPFSNode getIPFSNode(std::string hash) {

//   // find or create node
//   fs::path path = GetDataDir() / "Storage/Reputation";
//   std::string sReputation = openLevelDB(path.c_str(), hash);
//   // if(sReputation == "") return CIPFSNode(uint256S(hash));
//   return CIPFSNode(uint256S(hash), std::stoi(sReputation));

// }


// bool CIPFSNode::selectIPFSDeploy(std::vector<CIPFSNode> vIPFSList) {

//   //sort ipfsList with merge sort
//   // IPFSMergeSort(vIPFSList, 0, vIPFSList.size() - 1);

//   //put selected ipfs node into a vector
//   std::vector<CIPFSNode> selectedIPFSList;
//   if(vIPFSList.size() < (int)ipfs_max_select * ipfs_no_reputation_rate) {
//     selectedIPFSList = vIPFSList;
//   } else {
//     selectedIPFSList.insert(selectedIPFSList.end(), vIPFSList.begin(),
//                             vIPFSList.begin() + (int)ipfs_max_select * ipfs_no_reputation_rate);
//   }

//   //TODO: call contract to deploy func
//   return true;
// }

// bool processStorageContract(Contract contract){
//   if(contract.usage != contract_usage::USAGE_SYS) return false;
//   fs::fstream file;
//   fs::path pOutputPath = GetDataDir() / "Contract" / contract.address.GetHex() /"out";
//   file.open(pOutputPath,std::ios::in | std::ios::binary);

//   //determine owner of contract and contract state
//   if(checkContractOwner(contract.address.ToString())){
//     // receive ipfs list
//     if(contract.args[1]=="getIPFSlist"){
//       std::vector<CIPFSNode> vIPFSNodeList;
//       while(!file.eof()) {
//         char line[256];
//         file.getline(line,sizeof(line));
//         CIPFSNode node = getIPFSNode(line);
//         vIPFSNodeList.push_back(node);

//       }

//       selectIPFSDeploy(vIPFSNodeList);

//     }
//   } else {

//   }

//   return true;
// }
