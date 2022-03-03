#include <stdint.h>
#include <string.h>
#include <time.h>
#include <ourcontract.h>
#include "orc20.h"
#include "safe_math.h"

#define MAX_USER 1000
#define MAX_LENDERS 1000
#define MAX_LOANS 1000
#define MAX_CREDIT 100
// Oracle is an agent that supplies a convertion rate between ORC20 and NTD
#define ORACLE_ADDR "0xOracleAddress"
#define COINBASE ADDR "0x00"
#define INIT_ADDR "0x0"

const int RETRIEVE_REWARD = 50;
const int response_time_limit = 100;

/*
   Define your own data structure to store user data
*/

typedef struct token {
    char name[20];
    char symbol[10];
    char contractOwnerAddress[40];
    int decimal;
    int totalSupply;
} Token;

typedef struct account {
    char address[40];
    int balance;
} Account;

typedef struct allowance_record {
    char spender_address[40];
    int amount;
} AllowanceRecord;

typedef struct _allowance {
    char allownace_owner_address[40];
    int record_count;
    int allocated_array_size;

    // using pointer to have dynamic size array
    AllowanceRecord* records;
} Allowance;

typedef struct ipfsNode {
  char address[40];
  int available;
}IPFSNode;

typedef struct proofBlock {
  char cCIDHash[40];
  char cAddress[40];
  time_t time;
}ProofBlock;

typedef struct storageContractState {
  IPFSNode* aSignList; // ipfs node init sign up
  IPFSNode* aAuthList; // Authorize save node
  time_t end_time;
  char cCIDHash[46];
  ProofBlock* proof;
}StorageContractState;

typedef struct state {
    unsigned int size_contract; 
    unsigned int num_account;
    unsigned int allocated_account_array_size;
    unsigned int num_allowance;
    unsigned int allocated_allowance_array_size;
    unsigned int storage_contract_size;
} ContractState;
