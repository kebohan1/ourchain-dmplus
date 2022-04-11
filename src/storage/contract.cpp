
#include <storage/contract.h>

#include <contract/contract.h>
#include <contract/processing.h>
#include <core_io.h>
#include <cpprest/filestream.h>
#include <fstream>
#include "leveldb/db.h"
#include <util/system.h>
#include <wallet/wallet.h>
#include <wallet/rpcwallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>
#include <wallet/coincontrol.h>

using namespace utility; 

//TODO: select ipfs amount should be global setting
int ipfs_max_select = 4;

int ipfs_no_reputation_rate = 0.25;

uint256 deploySysContract(std::string blkname)
{
  //TODO: check amount of wallet
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

		if(pwallet->IsLocked()) {
			fprintf(stderr,"Error: Please enter the wallet passphrase with walletpassphrase first.");
			return uint256S("0");
		}
    
    //  CWalletTx wtx;
    CTransactionRef tx;
    CCoinControl no_coin_control;
    SendContractTx(pwallet, &contract, dest, tx, no_coin_control);

    //  

    return contract.address;
}

std::string openLevelDB(std::string path, std::string key) {
  leveldb::DB* db;
  leveldb::Options option;
  option.create_if_missing = false;
  leveldb::DB::Open(option, path, &db);
  leveldb::DB::Open(option, path, &db);
  std::string result;
  leveldb::Status status = db->Get(leveldb::ReadOptions(), key, &result);
  
  delete db;
  if(status.IsNotFound() == true) return "";
  return result;
}

bool checkContractOwner(std::string sContractHash) {
  fs::path path = GetDataDir() / "Storage/Contract";
  std::string sContractStatus = openLevelDB(path.c_str(), sContractHash);
  
  //if no data found or the status of contract is end, return false
  if(sContractHash=="" || (sContractHash != "" && sContractStatus == "-1")) return false;
  return true;
    
}

CIPFSNode getIPFSNode(std::string hash) {

  // find or create node
  fs::path path = GetDataDir() / "Storage/Reputation";
  std::string sReputation = openLevelDB(path.c_str(), hash);
  if(sReputation == "") return CIPFSNode(uint256S(hash));
  return CIPFSNode(uint256S(hash), std::stoi(sReputation));

}


bool selectIPFSDeploy(std::vector<CIPFSNode> vIPFSList) {
  
  //sort ipfsList with merge sort
  // IPFSMergeSort(vIPFSList, 0, vIPFSList.size() - 1);
  
  //put selected ipfs node into a vector
  std::vector<CIPFSNode> selectedIPFSList;
  if(vIPFSList.size() < (int)ipfs_max_select * ipfs_no_reputation_rate) {
    selectedIPFSList = vIPFSList;
  } else {
    selectedIPFSList.insert(selectedIPFSList.end(), vIPFSList.begin(),
                            vIPFSList.begin() + (int)ipfs_max_select * ipfs_no_reputation_rate);
  } 

  //TODO: call contract to deploy func
  return true;
}

bool processStorageContract(Contract contract){
  if(contract.usage != contract_usage::USAGE_SYS) return false;
  fs::fstream file;
  fs::path pOutputPath = GetDataDir() / "Contract" / contract.address.GetHex() /"out";
  file.open(pOutputPath,std::ios::in | std::ios::binary);
  
  //determine owner of contract and contract state
  if(checkContractOwner(contract.address.ToString())){
    // receive ipfs list
    if(contract.args[1]=="getIPFSlist"){
      std::vector<CIPFSNode> vIPFSNodeList;
      while(!file.eof()) {
        char line[256];
        file.getline(line,sizeof(line));
        CIPFSNode node = getIPFSNode(line);
        vIPFSNodeList.push_back(node);
        
      }

      selectIPFSDeploy(vIPFSNodeList);
      
    }
  } else {

  }

  return true;
}

