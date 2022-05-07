#include <contract/contract.h>
#include <core_io.h>
#include <fstream>
#include <util/system.h>

struct Token {
    char name[20];
    char symbol[10];
    char contractOwnerAddress[40];
    int decimal;
    int totalSupply;
};

struct Account {
    char address[40];
    int balance;
};

struct AllowanceRecord {
    char spender_address[40];
    int amount;
};

struct Allowance {
    char allownace_owner_address[40];
    int record_count;
    int allocated_array_size;

    // using pointer to have dynamic size array
    AllowanceRecord* records;
};

struct IPFSNode {
    char address[40];
    char ip[40];
    Account tokenAccount;
    int available;
    int nBlockNum;
};

struct ProofBlock {
    char cCIDHash[50];
    char cChallengeCIDHash[50];
    char cAddress[40];
    time_t time;
};

struct Block {
    int nBlockSavers;
    int allocated_blockSavers_size;
    int allocated_array_proof_size;
    int num_proof;
    char CIDHash[50];
    char merkleRoot[65]; // the length of merkle root is 256 bit
    char tfileCID[50];
    char tagCID[50];
    int* blockSavers;
    ProofBlock* array_proof_block;
};

struct ContractState {
    unsigned int size_contract;
    unsigned int num_account;
    unsigned int allocated_account_array_size;
    unsigned int num_allowance;
    unsigned int allocated_allowance_array_size;
    unsigned int num_ipfsnode;
    unsigned int allocated_ipfsnode_array_size;
    unsigned int num_blocks;
    unsigned int allocated_blocks_array_size;
    unsigned int num_replication;
};

class IpfsContract : Contract
{
public:
    Token ourToken;
    Account* globalAccountArray;
    Allowance* globalAllowanceArray;
    IPFSNode* aIpfsNode;
    ContractState theContractState;
    Block* aBlocks;
    int nInit = 0;

    IpfsContract(Contract contract) : Contract(contract)
    {
        init();
    }

    ~IpfsContract()
    {
        freeAccountArray();
        freeAllowanceArray();
        freeBlocksArray();
        freeIpfsNodeArray();
    }

    void init();
    uint256 getAddress()
    {
        return address;
    }

    std::vector<std::string> getArgs()
    {
        return args;
    }
    unsigned int readContractState(unsigned char* buffer, unsigned int offset);
    unsigned int readToken(unsigned char* buffer, unsigned int offset);
    unsigned int readAccountArray(unsigned char* buffer, unsigned int offset);
    unsigned int readAllowanceArray(unsigned char* buffer, unsigned int offset);
    unsigned int readBlocksArray(unsigned char* buffer, unsigned int offset);
    unsigned int readIpfsNodeArray(unsigned char* buffer, unsigned int offset);

    void freeAccountArray();
    void freeAllowanceArray();
    void freeBlocksArray();
    void freeIpfsNodeArray();

    unsigned int compute_contract_size()
    {
        unsigned int size_sum = 0;

        unsigned int sz_token = sizeof(Token);
        unsigned int sz_contract_state = sizeof(ContractState);
        unsigned int sz_account_array =
            sizeof(Account) * theContractState.allocated_account_array_size;
        unsigned int sz_allowance_array =
            sizeof(Allowance) * theContractState.allocated_allowance_array_size;
        unsigned int sz_allowance_records = 0;
        for (int i = 0; i < theContractState.num_allowance; i++) {
            sz_allowance_records +=
                globalAllowanceArray[i].allocated_array_size * sizeof(AllowanceRecord);
        }
        unsigned int sz_blocks_array =
            sizeof(Block) * theContractState.allocated_blocks_array_size;
        unsigned int sz_proofs_array = 0;
        unsigned int sz_savers_array = 0;
        for (int i = 0; i < theContractState.num_blocks; ++i) {
            sz_proofs_array +=
                aBlocks[i].allocated_array_proof_size * sizeof(ProofBlock);
            sz_savers_array += aBlocks[i].allocated_blockSavers_size * sizeof(int);
        }
        unsigned int sz_ipfsnode_array =
            sizeof(IPFSNode) * theContractState.allocated_ipfsnode_array_size;

        size_sum = sz_token + sz_contract_state + sz_account_array +
                   sz_allowance_array + sz_allowance_records + sz_blocks_array +
                   sz_proofs_array + sz_savers_array + sz_ipfsnode_array;
        return size_sum;
    }

    std::vector<uint256> getSavedBlock(std::string& pubkey);
    int findUser(std::string pubkey);
    Block* findBlock(std::string);
};
