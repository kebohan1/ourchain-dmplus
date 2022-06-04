#include <clientversion.h>
#include <consensus/validation.h>
#include <contract/contract.h>
#include <fs.h>
#include <pubkey.h>
#include <storage/contract.h>
#include <storage/ipfs.h>
#include <storage/ipfs_interface.h>
#include <streams.h>
#include <wallet/coincontrol.h>
#include <wallet/rpcwallet.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/walletutil.h>
#define COLDPOOL_MAX 30

using std::chrono::duration_cast;
using std::chrono::milliseconds;
using std::chrono::seconds;
using std::chrono::system_clock;

static CWallet* getWallet()
{
    std::vector<std::shared_ptr<CWallet>> wallets = GetWallets();
    std::shared_ptr<CWallet> const wallet = wallets.size() == 1 || wallets.size() > 0 ? wallets[0] : nullptr;

    if (wallet == nullptr) return nullptr;
    // if (contractHash.IsNull()) return;

    CWallet* const pwallet = wallet.get();

    LOCK(pwallet->cs_wallet);

    if (!pwallet->IsLocked())
        pwallet->TopUpKeyPool();
    // Generate a new key that is added to wallet

    if (pwallet->IsLocked()) {
        fprintf(stderr, "Error: Please enter the wallet passphrase with walletpassphrase first.");
        return nullptr;
    }


    return pwallet;
}

static CTxDestination getDest(CWallet* const pwallet)
{
    CPubKey newKey;
    CTxDestination dest;

    if (!pwallet->GetKeyFromPool(newKey)) {
        fprintf(stderr, "Error: Keypool ran out, please call keypoolrefill first");
        return dest;
    }

    CKeyID keyID = newKey.GetID();
    OutputType output_type = pwallet->m_default_change_type != OutputType::CHANGE_AUTO ? pwallet->m_default_change_type : pwallet->m_default_address_type;
    dest = GetDestinationForKey(newKey, output_type);

    std::string strAccount;
    pwallet->SetAddressBook(dest, strAccount, "receive");

    // sendtoaddress

    //  CBitcoinAddress address(CBitcoinAddress(keyID).ToString());
    if (!IsValidDestination(dest)) {
        fprintf(stderr, "Invalid Bitcoin address");
    }

    return dest;
}

static bool SendTx(CWallet* const pwallet, const Contract* contract, const CTxDestination& address, CTransactionRef& wtxNew, const CCoinControl& coin_control, string& strError)
{
    //  CAmount curBalance = pwallet->GetBalance();
    auto locked_chain = pwallet->chain().lock();
    if (pwallet->GetBroadcastTransactions() && !pwallet->chain().p2pEnabled())
        strError = "Error: Peer-to-peer functionality missing or disabled";
    return false;

    // Parse Bitcoin address
    CScript scriptPubKey = GetScriptForDestination(address);

    // Create and send the transaction
    CReserveKey reservekey(pwallet);
    CAmount nFeeRequired;
    std::vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    //  CRecipient recipient = {scriptPubKey, curBalance, true};
    CRecipient recipient = {scriptPubKey, 0, false};
    vecSend.push_back(recipient);
    if (!pwallet->CreateTransaction(*locked_chain, vecSend, wtxNew, reservekey, nFeeRequired, nChangePosRet, strError, coin_control, true, contract, true)) {
        return false;
    }
    CValidationState state;
    mapValue_t mapValue;
    if (!pwallet->CommitTransaction(wtxNew, std::move(mapValue), {} /* orderForm */, reservekey, state)) {
        //  if (!pwallet->CommitTransaction(wtxNew, reservekey, g_connman.get(), state)) {
        strError = strprintf("Error: The transaction was rejected! Reason given: %s", state.GetRejectReason());
        return false;
    }
}

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

static int64_t getTime(){
    return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

void IpfsStorageManager::receiveMessage(CStorageMessage msg)
{
    // LogPrintf("Process Storage Reqeust Msg, size: %d\n",msgs.size());
    // LogPrintf("The smart contract key store is : %s\n",RegisterKey);
    
    std::vector<string> ipfsTimeStamp;
    std::vector<string> appHash;
    // LogPrintf("CID: %s,TagCID: %s,ChallengeCID: %s\n", msg.CID, msg.TagCID, msg.firstChallengeCID);
    // LogPrintf("memory before: %d\n", getValue());
    // if (vStoredBlock.find(msg.hash) != vStoredBlock.end()) return;
    Contract contract;
    contract.address = contractHash;
    fs::path contractState = GetDataDir() / "contracts" / msg.hash.ToString() / "state";
    Block* oldBlock;
    if (fs::exists(contractState)) {
        IpfsContract oldContract{contract};
        oldBlock = oldContract.findBlock(msg.hash.ToString());
        if (oldBlock != nullptr) {
            LogPrintf("Find block in state\n");
            // free(oldBlock);
            return;
        }
    }

    vReadySolvingMsg.push_back(msg);
    ipfsTimeStamp.push_back(getTime()+","+msg.hash.ToString()+",recieve");
    int nColdPoolMax = gArgs.GetArg("-coldpool", 29);
    if (vReadySolvingMsg.size() < nColdPoolMax) return;
    if (RegisterKey.empty()) return;
    CWallet* const pwallet = getWallet();
    CTxDestination dest = getDest(pwallet);
    EnsureWalletIsUnlocked(pwallet);
    if (pwallet->IsLocked()) return;

    contract.args.push_back("save_blocks");
    contract.args.push_back(RegisterKey); // pubkey
    contract.args.push_back(to_string(vReadySolvingMsg.size()));
    contract.action = contract_action::ACTION_CALL;
    contract.usage = contract_usage::USAGE_USER;
    if(!fs::exists(GetDataDir()/"contracts"/contract.address.ToString()/"state")) return;
    IpfsContract oldContract{contract};
    int savingNum = 0;
    for (auto readymsg : vReadySolvingMsg) {
        oldBlock = oldContract.findBlock(readymsg.hash.ToString());
        if (oldBlock != nullptr) {
            LogPrintf("Find block in state\n");
            // free(oldBlock);
            continue;
        }
        ipfsTimeStamp.push_back(getTime()+","+msg.hash.ToString()+",process_start");
        PinIPFS(readymsg.CID);
        PinIPFS(readymsg.TagCID);
        // LogPrintf("IPFS get cmp\n");
        // std::cout << "Get All needed file cmp" <<std::endl;
        
        
        CPOR_challenge* pchallenge = UnserializeChallenge(StrHex(GetFromIPFS(readymsg.firstChallengeCID)));
        ipfsTimeStamp.push_back(getTime()+","+msg.hash.ToString()+",create_proof_start");
        CPOR_proof* pproof = cpor_prove_file(GetFromIPFS(readymsg.CID),
                                            StrHex(GetFromIPFS(readymsg.TagCID)),
                                            pchallenge);
        ipfsTimeStamp.push_back(getTime()+","+msg.hash.ToString()+",create_proof_end");
        std::string proofCID = AddToIPFS(HexStr(SerializeProof(pproof)));
        // LogPrintf("Serialize IPFS cmp\n");
        // std::cout << "Unserialize CPOR_challenge" << UnserializeChallenge(StrHex(challenge))->I <<std::endl;


        // LogPrintf("IPFS signup output: %s\n", contractHash.ToString());
// 

        contract.args.push_back(readymsg.hash.ToString());
        contract.args.push_back(readymsg.CID);

        contract.args.push_back(proofCID); // proofCID
        contract.args.push_back(readymsg.tFileCID);
        contract.args.push_back(readymsg.firstChallengeCID);
        contract.args.push_back(readymsg.TagCID);
        contract.args.push_back(std::to_string(time(NULL))); // time


        //  CWalletTx wtx;

        // std::cout << "Send Contract cmp:" << tx->GetHash().GetHex() << std::endl;
        destroy_cpor_proof(pproof);
        destroy_cpor_challenge(pchallenge);
        // IpfsStoredBlock cblock;
        // cblock.CID = readymsg.CID;
        // cblock.hash = readymsg.hash;
        // cblock.TagCID = readymsg.TagCID;
        // vStoredBlock.insert(std::pair<uint256, IpfsStoredBlock>(readymsg.hash, cblock));
        ++savingNum;
        appHash.push_back(msg.hash.ToString());
    }

    // LogPrintf("argc: %d\n", contract.args.size());
    CTransactionRef tx;
    CCoinControl no_coin_control;
    std::string error;
    SendContractTx(pwallet, &contract, dest, tx, no_coin_control);
    auto time = getTime();
    for(auto hash : appHash){
        ipfsTimeStamp.push_back(time+","+hash+",contract_end");
    }
    vReadySolvingMsg.clear();
    fs::path csvPath = GetDataDir() / "ipfs.csv";
    std::fstream csvStream;
    csvStream.open(csvPath.string(), ios::app);
    for(auto & writeStr: ipfsTimeStamp){
        csvStream << writeStr << std::endl;
    }
    csvStream.close();
    // LogPrintf("memory after: %d\n", getValue());

    // LogPrintf("Process Cmp\n");
    // DynamicStoreBlocks(savingNum);
}

void IpfsStorageManager::receiveChallengeMessage(ChallengeMessage msg)
{
    CWallet* const pwallet = getWallet();
    CTxDestination dest = getDest(pwallet);
    EnsureWalletIsUnlocked(pwallet);

    // LogPrintf("Recieve Challenge\n");
    // LogPrintf("memory before: %d\n", getValue());
    std::vector<string> ipfsTimeStamp;
    std::vector<string> appHash;
    Contract contract;

    contract.action = contract_action::ACTION_CALL;
    contract.usage = contract_usage::USAGE_USER;
    contract.address = contractHash;
    contract.args.push_back("proof_blocks");
    contract.args.push_back(RegisterKey); // pubkey
    IpfsContract oldContract{contract};
    // LogPrintf("Msg size: %d\n", msg.vChallenge.size());
    for (auto& item : msg.vChallenge) {
        // LogPrintf("block hash: %s\n", item.first.ToString());
        ipfsTimeStamp.push_back(getTime()+","+item.first.ToString()+",start_generating_proof");
        Block* oldBlock = oldContract.findBlock(item.first.ToString());
        if (oldBlock == nullptr) continue;
        std::string block = GetFromIPFS(oldBlock->CIDHash);
        std::string challenge = GetFromIPFS(item.second);
        std::string tag = GetFromIPFS(oldBlock->tagCID);
        CPOR_challenge* pchallenge = UnserializeChallenge(StrHex(challenge));
        // LogPrintf("Challenge recieve\n");
        CPOR_proof* pproof = cpor_prove_file(block, StrHex(tag), pchallenge);
        ipfsTimeStamp.push_back(getTime()+","+item.first.ToString()+",end_generating_proof");
        std::string proofCID = AddToIPFS(HexStr(SerializeProof(pproof)));
        // LogPrintf("Challenge prove created\n");

        // LogPrintf("IPFS signup output: %s\n",contractHash.ToString());
        /*
         * argv[n]: merkle root
         * argv[n + 1]: proof CID
         * argv[n + 2]: challenge CID
         * argv[n + 3]: time
         */

        contract.args.push_back(item.first.ToString());
        contract.args.push_back(proofCID); // proofCID
        contract.args.push_back(item.second);
        contract.args.push_back(std::to_string(time(NULL))); // time

        // delete(oldBlock);
        destroy_cpor_challenge(pchallenge);
        destroy_cpor_proof(pproof);
        appHash.push_back(item.first.ToString());
    }
    // LogPrintf("memory before submit tx: %d\n", getValue());
    CTransactionRef tx;
    CCoinControl no_coin_control;
    SendContractTx(pwallet, &contract, dest, tx, no_coin_control);
    auto time  = getTime();
    for(auto hash : appHash){
        ipfsTimeStamp.push_back(time+","+hash+",contract_end");
    }
    fs::path csvPath = GetDataDir() / "ipfsProve.csv";
    std::fstream csvStream;
    csvStream.open(csvPath.string(), ios::app);
    for(auto & writeStr: ipfsTimeStamp){
        csvStream << writeStr << std::endl;
    }
    csvStream.close();
    // LogPrintf("memory after: %d\n", getValue());
}

void IpfsStorageManager::init()
{
    fs::path managerpath = GetCPORDir() / "imanager.dat";
    CAutoFile cfilemanager(fsbridge::fopen(managerpath, "rb"), SER_DISK, CLIENT_VERSION);
    if (!cfilemanager.IsNull()) {
        cfilemanager >> *this;
    }
}

void IpfsStorageManager::FlushDisk()
{
    fs::path path = GetCPORDir() / "imanager.dat";
    CAutoFile cfilemanagerOut(fsbridge::fopen(path, "wb"), SER_DISK, CLIENT_VERSION);
    size_t nSize = GetSerializeSize(*this, cfilemanagerOut.GetVersion());
    cfilemanagerOut << *this << nSize;
}

bool blockNumCompare(Block a, Block b)
{
    return a.nBlockSavers < b.nBlockSavers;
}

bool blockNumDESC(Block a, Block b)
{
    return a.nBlockSavers > b.nBlockSavers;
}

void IpfsStorageManager::DynamicStoreBlocks(int already_stored_num)
{
    Contract contract;
    contract.address = contractHash;
    LogPrintf("DynamicStoreBlocks\n");
    fs::path csvPath = GetDataDir() / "dynamic.csv";
    auto newTime = duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
    fs::path stateFile = GetDataDir() / "contracts" / contractHash.ToString() / "state";
    if (!fs::exists(stateFile)) return;
    IpfsContract ipfsCon(contract);
    if (ipfsCon.nInit == 0) return;
    std::fstream csvStream;
    if (ipfsCon.findUser(RegisterKey) == -1) return;
    csvStream.open(csvPath.string(), ios::app);
    int recvContractNum = ipfsCon.getSavedBlock(RegisterKey).size() + already_stored_num;
    csvStream << newTime << "," << recvContractNum << std::endl;
    if (recvContractNum < (ipfsCon.theContractState.num_blocks + already_stored_num) / ipfsCon.theContractState.num_ipfsnode * ipfsCon.theContractState.num_replication) {
        std::sort(ipfsCon.aBlocks,
            ipfsCon.aBlocks + ipfsCon.theContractState.num_blocks,
            blockNumCompare);
        int saveBlocks = recvContractNum;
        CWallet* const pwallet = getWallet();
        CTxDestination dest = getDest(pwallet);
        EnsureWalletIsUnlocked(pwallet);
        Contract contract;

        contract.action = contract_action::ACTION_CALL;
        contract.usage = contract_usage::USAGE_USER;
        contract.address = contractHash;
        contract.args.push_back("dynamic_save_blocks");
        std::vector<std::string> args;

        for (int i = 0; i < ipfsCon.theContractState.num_blocks; ++i) {
            if (vStoredBlock.find(uint256S(ipfsCon.aBlocks[i].merkleRoot)) == vStoredBlock.end() && saveBlocks < ipfsCon.theContractState.num_blocks / ipfsCon.theContractState.num_ipfsnode * ipfsCon.theContractState.num_replication) {
                PinIPFS(ipfsCon.aBlocks[i].CIDHash);
                PinIPFS(ipfsCon.aBlocks[i].tagCID);

                // LogPrintf("IPFS signup output: %s\n",contractHash.ToString());
                /*
                 * Argc num = 6
                 * argv[2]: merkle root
                 * argv[3]: CID
                 * argv[4]: ipfs pubkey
                 * argv[5]: time
                 */

                args.push_back(ipfsCon.aBlocks[i].merkleRoot);
                args.push_back(ipfsCon.aBlocks[i].CIDHash);
                // pubkey
                args.push_back(std::to_string(time(NULL))); // time


                saveBlocks++;
            }
        }


        contract.args.push_back(RegisterKey);
        contract.args.push_back(std::to_string(args.size()));
        contract.args.insert(contract.args.end(), args.begin(), args.end());
        CTransactionRef tx;
        CCoinControl no_coin_control;
        SendContractTx(pwallet, &contract, dest, tx, no_coin_control);
    } else if (recvContractNum > (ipfsCon.theContractState.num_blocks + already_stored_num) / ipfsCon.theContractState.num_ipfsnode * ipfsCon.theContractState.num_replication) {
        std::sort(ipfsCon.aBlocks,
            ipfsCon.aBlocks + ipfsCon.theContractState.num_blocks,
            blockNumDESC);
        int saveBlocks = recvContractNum;
        CWallet* const pwallet = getWallet();
        CTxDestination dest = getDest(pwallet);
        EnsureWalletIsUnlocked(pwallet);
        for (int i = 0; i < ipfsCon.theContractState.num_blocks; ++i) {
            if (vStoredBlock.find(uint256S(ipfsCon.aBlocks[i].merkleRoot)) != vStoredBlock.end() && ipfsCon.aBlocks[i].nBlockSavers > ipfsCon.theContractState.num_replication && saveBlocks > ipfsCon.theContractState.num_blocks / ipfsCon.theContractState.num_ipfsnode * ipfsCon.theContractState.num_replication) {
                // TODO: UnPinFromIPFS
                // PinIPFS(ipfsCon.aBlocks[i].CIDHash);
                // PinIPFS(ipfsCon.aBlocks[i].tagCID);
                Contract contract;

                contract.action = contract_action::ACTION_CALL;
                contract.usage = contract_usage::USAGE_USER;
                contract.address = contractHash;
                // LogPrintf("IPFS signup output: %s\n",contractHash.ToString());
                /*
                 * Argc num = 3
                 * argv[2]: merkle_root
                 * argv[3]: ipfs pubkey
                 */
                contract.args.push_back("remove_block");
                contract.args.push_back(ipfsCon.aBlocks[i].merkleRoot);
                contract.args.push_back(RegisterKey); // pubkey

                CTransactionRef tx;
                CCoinControl no_coin_control;
                SendContractTx(pwallet, &contract, dest, tx, no_coin_control);
                saveBlocks--;
            }
        }
    }
    csvStream.close();
    ipfsCon.theContractState.num_blocks;
}