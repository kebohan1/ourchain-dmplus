#include <clientversion.h>
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

void IpfsStorageManager::receiveMessage(CStorageMessage msg)
{
    // LogPrintf("Process Storage Reqeust Msg, size: %d\n",msgs.size());
    // LogPrintf("The smart contract key store is : %s\n",RegisterKey);

    CWallet* const pwallet = getWallet();
    CTxDestination dest = getDest(pwallet);
    // EnsureWalletIsUnlocked(pwallet);
    if(pwallet->IsLocked()) return;


    LogPrintf("CID: %s,TagCID: %s,ChallengeCID: %s\n",msg.CID,msg.TagCID,msg.firstChallengeCID);
    if (vStoredBlock.find(msg.hash) != vStoredBlock.end()) return;
    PinIPFS(msg.CID);
    PinIPFS(msg.TagCID);
    std::string block = GetFromIPFS(msg.CID);
    std::string tag = GetFromIPFS(msg.TagCID);
    std::string challenge = GetFromIPFS(msg.firstChallengeCID);
    LogPrintf("IPFS get cmp\n");
    // std::cout << "Get All needed file cmp" <<std::endl;

    CPOR_challenge* pchallenge = UnserializeChallenge(StrHex(challenge));

    CPOR_proof* pproof = cpor_prove_file(block, StrHex(tag), pchallenge);
    std::string proofCID = AddToIPFS(HexStr(SerializeProof(pproof)));
    LogPrintf("Serialize IPFS cmp\n");
    // std::cout << "Unserialize CPOR_challenge" << UnserializeChallenge(StrHex(challenge))->I <<std::endl;
    Contract contract;

    contract.action = contract_action::ACTION_CALL;
    contract.usage = contract_usage::USAGE_USER;
    contract.address = contractHash;
    LogPrintf("IPFS signup output: %s\n",contractHash.ToString());

    contract.args.push_back("save_block");
    contract.args.push_back(msg.hash.ToString());
    contract.args.push_back(msg.CID);
    contract.args.push_back(RegisterKey); // pubkey
    contract.args.push_back(proofCID);    // proofCID
    contract.args.push_back(msg.tFileCID);
    contract.args.push_back(msg.firstChallengeCID);
    contract.args.push_back(msg.TagCID);
    contract.args.push_back(std::to_string(time(NULL))); // time


    //  CWalletTx wtx;
    CTransactionRef tx;
    CCoinControl no_coin_control;
    SendContractTx(pwallet, &contract, dest, tx, no_coin_control);
    // std::cout << "Send Contract cmp:" << tx->GetHash().GetHex() << std::endl;
    // free(pproof);
    free(pchallenge);
    IpfsStoredBlock cblock;
    cblock.CID = msg.CID;
    cblock.hash = msg.hash;
    cblock.TagCID = msg.TagCID;
    vStoredBlock.insert(std::pair<uint256, IpfsStoredBlock>(msg.hash, cblock));

    LogPrintf("Process Cmp\n");
    DynamicStoreBlocks(1);
}

void IpfsStorageManager::receiveChallengeMessage(ChallengeMessage msg)
{
    CWallet* const pwallet = getWallet();
    CTxDestination dest = getDest(pwallet);
    EnsureWalletIsUnlocked(pwallet);
    LogPrintf("Recieve Challenge\n");

    for (auto& item : msg.vChallenge) {
        std::string block = GetFromIPFS(vStoredBlock.find(item.first)->second.CID);
        std::string challenge = GetFromIPFS(item.second);
        std::string tag = GetFromIPFS(vStoredBlock.find(item.first)->second.TagCID);
        CPOR_challenge* pchallenge = UnserializeChallenge(StrHex(challenge));

        std::string proofCID = AddToIPFS(HexStr(SerializeProof(cpor_prove_file(block, StrHex(tag), pchallenge))));
        LogPrintf("Challenge prove created\n");
        Contract contract;

        contract.action = contract_action::ACTION_CALL;
        contract.usage = contract_usage::USAGE_USER;
        contract.address = contractHash;
        // LogPrintf("IPFS signup output: %s\n",contractHash.ToString());
        /*
         * argv[2]: merkle root
         * argv[3]: ipfs pubkey
         * argv[4]: proof CID
         * argv[5]: challenge CID
         * argv[6]: time
         */
        contract.args.push_back("proof_block");
        contract.args.push_back(item.first.ToString());
        contract.args.push_back(RegisterKey); // pubkey
        contract.args.push_back(proofCID);    // proofCID
        contract.args.push_back(item.second);
        contract.args.push_back(std::to_string(time(NULL))); // time

        CTransactionRef tx;
        CCoinControl no_coin_control;
        SendContractTx(pwallet, &contract, dest, tx, no_coin_control);

        destroy_cpor_challenge(pchallenge);
        // destroy_cpor_proof(pproof);
    }
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
    IpfsContract ipfsCon(contract);
    std::fstream csvStream;
    if (ipfsCon.findUser(RegisterKey) == -1) return;
    csvStream.open(csvPath.string(), ios::app);
    int recvContractNum = ipfsCon.getSavedBlock(RegisterKey).size() + already_stored_num;
    csvStream << recvContractNum << std::endl;
    if (recvContractNum < (ipfsCon.theContractState.num_blocks + already_stored_num) / ipfsCon.theContractState.num_ipfsnode * ipfsCon.theContractState.num_replication) {
        std::sort(ipfsCon.aBlocks,
            ipfsCon.aBlocks + ipfsCon.theContractState.num_blocks,
            blockNumCompare);
        int saveBlocks = recvContractNum;
        CWallet* const pwallet = getWallet();
        CTxDestination dest = getDest(pwallet);
        EnsureWalletIsUnlocked(pwallet);
        for (int i = 0; i < ipfsCon.theContractState.num_blocks; ++i) {
            if (vStoredBlock.find(uint256S(ipfsCon.aBlocks[i].merkleRoot)) == vStoredBlock.end() && saveBlocks < ipfsCon.theContractState.num_blocks / ipfsCon.theContractState.num_ipfsnode * ipfsCon.theContractState.num_replication) {
                PinIPFS(ipfsCon.aBlocks[i].CIDHash);
                PinIPFS(ipfsCon.aBlocks[i].tagCID);
                Contract contract;

                contract.action = contract_action::ACTION_CALL;
                contract.usage = contract_usage::USAGE_USER;
                contract.address = contractHash;
                // LogPrintf("IPFS signup output: %s\n",contractHash.ToString());
                /*
                 * Argc num = 6
                 * argv[2]: merkle root
                 * argv[3]: CID
                 * argv[4]: ipfs pubkey
                 * argv[5]: time
                 */
                contract.args.push_back("save_block");
                contract.args.push_back(ipfsCon.aBlocks[i].merkleRoot);
                contract.args.push_back(ipfsCon.aBlocks[i].CIDHash);
                contract.args.push_back(RegisterKey);                // pubkey
                contract.args.push_back(std::to_string(time(NULL))); // time

                CTransactionRef tx;
                CCoinControl no_coin_control;
                SendContractTx(pwallet, &contract, dest, tx, no_coin_control);
                saveBlocks++;
            }
        }
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
    ipfsCon.theContractState.num_blocks;
}