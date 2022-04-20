#include <storage/ipfs.h>
#include <storage/ipfs_interface.h>
#include <fs.h>
#include <streams.h>
#include <clientversion.h>
#include <contract/contract.h>
#include <storage/contract.h>
#include <wallet/coincontrol.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>
#include <pubkey.h>


void IpfsStorageManager::receiveMessage(std::vector<CStorageMessage> msgs) {
  // LogPrintf("Process Storage Reqeust Msg, size: %d\n",msgs.size());
  // LogPrintf("The smart contract key store is : %s\n",RegisterKey);
  std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
  std::shared_ptr<CWallet> const wallet = wallets.size() == 1 || wallets.size() > 0 ? wallets[0] : nullptr;
  
  if (wallet == nullptr) return;
  // if (contractHash.IsNull()) return;

  CWallet* const pwallet = wallet.get();

  LOCK(pwallet->cs_wallet);

  if (!pwallet->IsLocked())
        pwallet->TopUpKeyPool();
    // Generate a new key that is added to wallet
  CPubKey newKey;

  if (!pwallet->GetKeyFromPool(newKey)) {
      fprintf(stderr, "Error: Keypool ran out, please call keypoolrefill first");
      return ;
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
        return ;
    }

    if (pwallet->IsLocked()) {
        fprintf(stderr, "Error: Please enter the wallet passphrase with walletpassphrase first.");
        return ;
    }

    EnsureWalletIsUnlocked(pwallet);
    

  for(auto msg : msgs) {
    // std::cout << "CID: " << msg.CID << ",TagCID: " << msg.TagCID << ",ChallengeCID: " << msg.firstChallengeCID <<std::endl; 
    PinIPFS(msg.CID);
    PinIPFS(msg.TagCID);
    std::string block = GetFromIPFS(msg.CID);
    std::string tag = GetFromIPFS(msg.TagCID);
    std::string challenge = GetFromIPFS(msg.firstChallengeCID);
    // std::cout << "Get All needed file cmp" <<std::endl;
    
    CPOR_challenge* pchallenge = UnserializeChallenge(StrHex(challenge));
    
    CPOR_proof* pproof = cpor_prove_file(block,StrHex(tag),pchallenge);
    std::string proofCID = AddToIPFS(HexStr(SerializeProof(pproof)));
    // std::cout << "Unserialize CPOR_challenge" << UnserializeChallenge(StrHex(challenge))->I <<std::endl;
    Contract contract;

    contract.action = contract_action::ACTION_CALL;
    contract.usage = contract_usage::USAGE_USER;
    contract.address = contractHash;
    // LogPrintf("IPFS signup output: %s\n",contractHash.ToString());

    contract.args.push_back("save_block");
    contract.args.push_back(msg.hash.ToString());
    contract.args.push_back(msg.CID);
    contract.args.push_back(RegisterKey); //pubkey
    contract.args.push_back(proofCID); //proofCID
    contract.args.push_back(msg.tFileCID);
    contract.args.push_back(msg.firstChallengeCID);
    contract.args.push_back(std::to_string(time(NULL))); //time
    
    
    //  CWalletTx wtx;
    CTransactionRef tx;
    CCoinControl no_coin_control;
    SendContractTx(pwallet, &contract, dest, tx, no_coin_control);
    // std::cout << "Send Contract cmp:" << tx->GetHash().GetHex() << std::endl;
    // free(pproof);
    free(pchallenge);
  }
  // LogPrintf("Process Cmp\n");
}

void IpfsStorageManager::init(){
  fs::path managerpath = GetCPORDir() / "imanager.dat";
  CAutoFile cfilemanager(fsbridge::fopen(managerpath ,"rb"), SER_DISK, CLIENT_VERSION);
    if(!cfilemanager.IsNull()) {
      cfilemanager >> *this ;
    }
}

void IpfsStorageManager::FlushDisk(){
  fs::path path = GetCPORDir() / "imanager.dat";
  CAutoFile cfilemanagerOut(fsbridge::fopen(path ,"wb"), SER_DISK, CLIENT_VERSION);
  size_t nSize = GetSerializeSize(*this, cfilemanagerOut.GetVersion());
  cfilemanagerOut << *this << nSize;
}