#include <fstream>
#include <util/system.h>
#include <core_io.h>
#include <contract/contract.h>

struct Token {
    char name[20];
    char symbol[10];
    char contractOwnerAddress[40];
    int decimal;
    int totalSupply;
} ;

struct Account {
    char address[40];
    int balance;
} ;

struct AllowanceRecord {
    char spender_address[40];
    int amount;
} ;

struct Allowance {
    char allownace_owner_address[40];
    int record_count;
    int allocated_array_size;

    // using pointer to have dynamic size array
    AllowanceRecord* records;
} ;

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
  char merkleRoot[65];  // the length of merkle root is 256 bit
  char tfileCID[50];
  char tagCID[50];
  int* blockSavers;
  ProofBlock* array_proof_block;
} ;

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
} ;

class IpfsContract : Contract{
  public:
    Token ourToken;
    Account* globalAccountArray;
    Allowance* globalAllowanceArray;
    IPFSNode* aIpfsNode;
    ContractState theContractState;
    Block* aBlocks;
    int nInit = 0;

    IpfsContract(Contract contract) : Contract(contract){
      init();
    }

    ~IpfsContract(){
      freeAccountArray();
      freeAllowanceArray();
      freeBlocksArray();
      freeIpfsNodeArray();
    }

    void init();
    uint256 getAddress(){
      return address;
    }

    std::vector<std::string> getArgs(){
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

    std::vector<uint256> getSavedBlock(std::string pubkey);
    int findUser(std::string pubkey);
    Block* findBlock(std::string);
};
