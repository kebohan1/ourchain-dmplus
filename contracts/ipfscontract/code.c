#include <assert.h>
#include <ourcontract.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
// #include "orc20.h"
// #include "safe_math.h"
#include <cpor.h>
#include <netdb.h>
#include <sys/socket.h>

#define MAX_USER 1000
#define MAX_BLOCK_NUM 100000
#define INIT_BLOCK_PROOF_NUM 1000
// Oracle is an agent that supplies a convertion rate between ORC20 and NTD

#define COINBASE ADDR "0x00"
#define INIT_ADDR "0x0"

const int RETRIEVE_REWARD = 50;
const int response_time_limit = 100;

#define CONTRACT_INIT_FUNC "init"
#define INIT_ACCOUNT_ARRAY_SIZE 20
#define INIT_ALLOWANCE_ARRAY_SIZE 10
#define INIT_ALLOWANCE_RECORD_ARRAY_SIZE 5
#define INIT_IPFSNODE_ARRAY_SIZE 20
#define INIT_PROOF_ARRAY_SIZE 20
#define INIT_BLOCK_ARRAY_SIZE 100

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
  char ip[40];
  Account tokenAccount;
  int available;
  int nBlockNum;
} IPFSNode;

typedef struct proofBlock {
  char cCIDHash[50];
  char cChallengeCIDHash[50];
  char cAddress[40];
  time_t time;
} ProofBlock;

typedef struct block {
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
} Block;

typedef struct state {
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
} ContractState;

/* optional APIs */
char* symbol();
char* name();
int decimals();

/* required APIs */
int totalSupply();
int balanceOf(char*);
int allowance(char*, char*);
int approve(char*, char*, int);
int transfer(char*, char*, int);
int transferFrom(char*, char*, char*, int);

/* self-defined functions */
static void initAccountArray();
static Account* findAccount(char*);
static Account createAccount(char*);
static void appendToAccountArray(Account);

static void initAllowanceArray();
static Allowance* findAllowance(Account*);
static Allowance createAllowance(Account*);
static void appendToAllowanceArray(Allowance);

static void initIpfsArray();
static int findIPFSnode(char*);
static IPFSNode createIPFSnode(char*, char*);
static void appendToIpfsArray(IPFSNode);

static AllowanceRecord* findAllowanceRecord(Allowance*, Account*);
static AllowanceRecord createAllowanceRecord(Account*, int);
static void appendToAllowanceRecordArray(Allowance*, AllowanceRecord);

static unsigned int readState();
static unsigned int readContractState(unsigned char*, unsigned int);
static unsigned int readToken(unsigned char*, unsigned int);
static unsigned int readAccountArray(unsigned char*, unsigned int);
static unsigned int readAllowanceArray(unsigned char*, unsigned int);
static unsigned int readBlocksArray(unsigned char*, unsigned int);
static unsigned int readIpfsNodeArray(unsigned char*, unsigned int);

static unsigned int writeState();
static unsigned int writeTokenToState(unsigned char*, unsigned int);
static unsigned int writeContractStateToState(unsigned char*, unsigned int);
static unsigned int writeAccountArrayToState(unsigned char*, unsigned int);
static unsigned int writeAllowanceArrayToState(unsigned char*, unsigned int);
static unsigned int writeBlocksArray(unsigned char*, unsigned int);
static unsigned int writeIpfsNodeArray(unsigned char*, unsigned int);

static unsigned int compute_contract_size();

Account* globalAccountArray;
Allowance* globalAllowanceArray;
IPFSNode* aIpfsNode;  // ipfs node init sign up
Block* aBlocks;
Token ourToken;
ContractState theContractState;

/*
  Debug functions
  err_printf() will print to regtest/contracts/err
  out_printf() will print to regtest/contracts/<contract_id>/out

  Warning: DO NOT use printf(). Usually it will block your program
*/

void print_contract_state() {
  err_printf("%u,%u,%u,%u,%u\n", theContractState.size_contract,
             theContractState.num_account,
             theContractState.allocated_account_array_size,
             theContractState.num_allowance,
             theContractState.allocated_allowance_array_size);
  return;
}

void print_token() {
  err_printf("%s,%s,%s,%d,%d\n", ourToken.contractOwnerAddress, ourToken.name,
             ourToken.symbol, ourToken.decimal, ourToken.totalSupply);
  return;
}

void print_global_account_array() {
  for (int i = 0; i < theContractState.num_account; i++) {
    err_printf("%s,%d\n", globalAccountArray[i].address,
               globalAccountArray[i].balance);
  }
  return;
}

void print_global_allowance_array() {
  for (int i = 0; i < theContractState.num_allowance; i++) {
    err_printf("%s,%d\n", globalAllowanceArray[i].allownace_owner_address,
               globalAllowanceArray[i].record_count);
    for (int j = 0; j < globalAllowanceArray[i].record_count; j++) {
      err_printf("%s,%d\n", globalAllowanceArray[i].records[j].spender_address,
                 globalAllowanceArray[i].records[j].amount);
    }
  }
  return;
}

void print_sys_args(int argc, char** argv) {
  for (int i = 0; i < argc; i++) err_printf("%s,", argv[i]);
  err_printf("\n");
  return;
}

/*
   Implement your ERC20-like functions
*/

char* symbol() { return ourToken.symbol; }

char* name() { return ourToken.name; }

int decimals() { return ourToken.decimal; }

int totalSupply() { return ourToken.totalSupply; }

int balanceOf(char* requester_address) {
  Account* requester_account = findAccount(requester_address);

  if (requester_account == NULL) {
    err_printf("%s account not found\n", requester_address);
    return 0;
  }
  return requester_account->balance;
}

int allowance(char* token_owner_address, char* spender_address) {
  Account* token_owner_account = findAccount(token_owner_address);
  Account* spender_account = findAccount(spender_address);

  if (token_owner_account == NULL) {
    err_printf("%s account not found\n", token_owner_address);
    return 0;
  } else if (spender_account == NULL) {
    err_printf("%s account not found\n", spender_address);
    return 0;
  }

  Allowance* token_owner_allowance = findAllowance(token_owner_account);
  if (token_owner_allowance == NULL) {
    err_printf("%s allowance not found\n", token_owner_address);
    return 0;
  }

  AllowanceRecord* record =
      findAllowanceRecord(token_owner_allowance, spender_account);
  if (record == NULL) {
    err_printf("%s allowance not found\n", spender_address);
    return 0;
  }

  return record->amount;
}

int approve(char* token_owner_address, char* spender_address, int amount) {
  if (amount < 0) {
    err_printf("error:amount < 0\n");
    return -1;
  }

  Account* token_owner_account = findAccount(token_owner_address);
  if (token_owner_account == NULL) {
    err_printf("%s account not found\n", token_owner_address);
    return -1;
    // appendToAccountArray(createAccount(token_owner_address));
    // token_owner_account = findAccount(token_owner_address);
  }

  Allowance* token_owner_allowance = findAllowance(token_owner_account);
  if (token_owner_allowance == NULL) {
    appendToAllowanceArray(createAllowance(token_owner_account));
    token_owner_allowance = findAllowance(token_owner_account);
  }

  Account* spender_account = findAccount(spender_address);
  if (spender_account == NULL) {
    err_printf("%s account not found\n", spender_address);
    return -1;
    // appendToAccountArray(createAccount(spender_address));
    // spender_account = findAccount(spender_address);
  }

  AllowanceRecord* record =
      findAllowanceRecord(token_owner_allowance, spender_account);
  if (record == NULL) {
    appendToAllowanceRecordArray(
        token_owner_allowance, createAllowanceRecord(spender_account, amount));
    record = findAllowanceRecord(token_owner_allowance, spender_account);
  } else {
    record->amount = amount;
  }

  return 0;
}

int transfer(char* msg_sender_address, char* to_address, int amount) {
  Account* msg_sender_account = findAccount(msg_sender_address);
  if (msg_sender_account == NULL) {
    err_printf("%s account not found\n", msg_sender_address);
    return -1;
  }

  Account* to_account = findAccount(to_address);
  if (to_account == NULL) {
    err_printf("%s account not found\n", to_address);
    return -1;
    // appendToAccountArray(createAccount(to_address));
    // to_account = findAccount(to_address);
  }

  if (msg_sender_account->balance >= amount && amount > 0) {
    to_account->balance += amount;
    msg_sender_account->balance -= amount;
    return 0;
  }

  err_printf("insufficient funds\n");
  return -1;
}

int transferFrom(char* msg_sender_address, char* token_onwer_address,
                 char* to_address, int amount) {
  Account* msg_sender_account = findAccount(msg_sender_address);
  if (msg_sender_account == NULL) {
    err_printf("%s account not found\n", msg_sender_address);
    return -1;
  }

  Account* token_owner_account = findAccount(token_onwer_address);
  if (token_owner_account == NULL) {
    err_printf("%s account not found\n", token_onwer_address);
  }

  Account* to_account = findAccount(to_address);
  if (to_account == NULL) {
    err_printf("%s account not found\n", to_address);
    return -1;
    // appendToAccountArray(createAccount(to_address));
    // to_account = findAccount(to_address);
  }

  int allowance_value = allowance(token_onwer_address, msg_sender_address);

  if (token_owner_account->balance >= amount && allowance_value >= amount &&
      amount > 0) {
    Allowance* token_owner_allowance = findAllowance(token_owner_account);
    AllowanceRecord* record =
        findAllowanceRecord(token_owner_allowance, msg_sender_account);

    token_owner_account->balance -= amount;
    record->amount -= amount;
    to_account->balance += amount;

    return 0;
  }

  return -1;
}

/*
    The following functions are used to
        * store your program data
        * read your program data
        * data structure related method
        * serialize data structure
*/

static unsigned int readState() {
  /*
      Use state_read() to read your program data
      The data are stored in memory, tight together with UTXO so it will revert
     automatically

      state_read(buff, size) is straightforward: read `size` bytes to `buff`
      The point is how you define your structure and serialize it

      The following code is just one of the way to read state
          * In write stage:
          * you first write how many byte you stored
          * then write all your data
          * In read stage:
          * first get the size of data
          * then get all the data
          * unserialize the data
  */

  unsigned int count;
  state_read(&count, sizeof(int));

  unsigned char* buff = malloc(sizeof(char) * count);
  unsigned int offset = 0;
  state_read(buff, count);

  offset += readContractState(buff, offset);
  offset += readToken(buff, offset);
  offset += readAccountArray(buff, offset);
  offset += readAllowanceArray(buff, offset);
  offset += readBlocksArray(buff, offset);
  offset += readIpfsNodeArray(buff, offset);

  if (offset != count) {
    err_printf("offset = %u  count = %u\n", offset, count);
    assert(offset == count);
  }
  free(buff);
  return offset;
}

static unsigned int readContractState(unsigned char* buffer,
                                      unsigned int offset) {
  memcpy(&theContractState, buffer + offset, sizeof(ContractState));
  return sizeof(ContractState);
}

static unsigned int readToken(unsigned char* buffer, unsigned int offset) {
  memcpy(&ourToken, buffer + offset, sizeof(Token));
  return sizeof(Token);
}

static unsigned int readAccountArray(unsigned char* buffer,
                                     unsigned int offset) {
  globalAccountArray =
      malloc(sizeof(Account) * theContractState.allocated_account_array_size);
  memcpy(globalAccountArray, buffer + offset,
         sizeof(Account) * theContractState.allocated_account_array_size);
  return sizeof(Account) * theContractState.allocated_account_array_size;
}

static unsigned int readAllowanceArray(unsigned char* buffer,
                                       unsigned int offset) {
  unsigned int written_bytes = 0;
  globalAllowanceArray = malloc(
      sizeof(Allowance) * theContractState.allocated_allowance_array_size);

  for (int i = 0; i < theContractState.allocated_allowance_array_size; i++) {
    memcpy(&globalAllowanceArray[i], buffer + offset, sizeof(Allowance));
    written_bytes += sizeof(Allowance);
    offset += sizeof(Allowance);

    if (i <= theContractState.num_allowance) {
      globalAllowanceArray[i].records =
          malloc(sizeof(AllowanceRecord) *
                 globalAllowanceArray[i].allocated_array_size);
      memcpy(globalAllowanceArray[i].records, buffer + offset,
             sizeof(AllowanceRecord) *
                 globalAllowanceArray[i].allocated_array_size);
      written_bytes += sizeof(AllowanceRecord) *
                       globalAllowanceArray[i].allocated_array_size;
      offset += sizeof(AllowanceRecord) *
                globalAllowanceArray[i].allocated_array_size;
    }
  }

  return written_bytes;
}

static unsigned int readBlocksArray(unsigned char* buffer,
                                    unsigned int offset) {
  unsigned int written_bytes = 0;
  aBlocks =
      malloc(sizeof(Block) * theContractState.allocated_blocks_array_size);

  for (int i = 0; i < theContractState.allocated_blocks_array_size; ++i) {
    memcpy(&aBlocks[i], buffer + offset, sizeof(Block));
    written_bytes += sizeof(Block);
    offset += sizeof(Block);

    if (i <= theContractState.num_blocks) {
      aBlocks[i].blockSavers =
          malloc(sizeof(int) * aBlocks[i].allocated_blockSavers_size);
      memcpy(aBlocks[i].blockSavers, buffer + offset,
             sizeof(int) * aBlocks[i].allocated_blockSavers_size);
      written_bytes += sizeof(int) * aBlocks[i].allocated_blockSavers_size;
      offset += sizeof(int) * aBlocks[i].allocated_blockSavers_size;

      aBlocks[i].array_proof_block =
          malloc(sizeof(ProofBlock) * aBlocks[i].allocated_array_proof_size);
      memcpy(aBlocks[i].array_proof_block, buffer + offset,
             sizeof(ProofBlock) * aBlocks[i].allocated_array_proof_size);
      written_bytes +=
          sizeof(ProofBlock) * aBlocks[i].allocated_array_proof_size;
      offset += sizeof(ProofBlock) * aBlocks[i].allocated_array_proof_size;
    }
  }

  return written_bytes;
}
static unsigned int readIpfsNodeArray(unsigned char* buffer,
                                      unsigned int offset) {
  aIpfsNode =
      malloc(sizeof(IPFSNode) * theContractState.allocated_ipfsnode_array_size);
  memcpy(aIpfsNode, buffer + offset,
         sizeof(IPFSNode) * theContractState.allocated_ipfsnode_array_size);
  return sizeof(IPFSNode) * theContractState.allocated_ipfsnode_array_size;
}

static void releaseState() {
  // err_printf("Free globalAccountArray\n");
  if (globalAccountArray) free(globalAccountArray);
  // err_printf("Free aIpfsNode\n");

  if (aIpfsNode) free(aIpfsNode);
  // err_printf("Free globalAllowanceArray\n");

  if (globalAllowanceArray) free(globalAllowanceArray);
  for (int i = 0; i < theContractState.num_blocks; i++) {  
    free(aBlocks[i].blockSavers);
    free(aBlocks[i].array_proof_block);
  }
  // err_printf("Free aBlocks\n");

  if (aBlocks) free(aBlocks);
  // err_printf("Free cmp\n");
}

static unsigned int writeState() {
  /*
      Use state_write() to write your program data
      The data are stored in memory, tight together with UTXO so it will revert
     automatically

      state_read(buff, size) is straightforward: write `size` bytes from `buff`

      Warning: You need to write all your data at once.
      The state is implement as a vector, and will resize every time you use
     state_write So if you write multiple times, it will be the size of last
     write

      One way to solve this is you memcpy() all your serialized data to a big
     array and then call only one time state_write()
  */

  unsigned char* buff =
      malloc(sizeof(int) + sizeof(char) * theContractState.size_contract);
  unsigned int offset = 0;

  memcpy(buff, &theContractState.size_contract, sizeof(int));
  offset += sizeof(int);

  offset += writeContractStateToState(buff, offset);
  offset += writeTokenToState(buff, offset);
  offset += writeAccountArrayToState(buff, offset);
  offset += writeAllowanceArrayToState(buff, offset);
  offset += writeBlocksArray(buff, offset);
  offset += writeIpfsNodeArray(buff, offset);

  err_printf("offset: %d, real size: %d\n", offset,
             theContractState.size_contract);
  assert(offset == sizeof(int) + sizeof(char) * theContractState.size_contract);
  state_write(buff, offset);

  // free(buff);
  releaseState();
  // free(buff);
  return offset;
}

static unsigned int writeContractStateToState(unsigned char* buffer,
                                              unsigned int offset) {
  memcpy(buffer + offset, &theContractState, sizeof(ContractState));
  return sizeof(ContractState);
}

static unsigned int writeTokenToState(unsigned char* buffer,
                                      unsigned int offset) {
  memcpy(buffer + offset, &ourToken, sizeof(Token));
  return sizeof(Token);
}

static unsigned int writeAccountArrayToState(unsigned char* buffer,
                                             unsigned int offset) {
  memcpy(buffer + offset, globalAccountArray,
         sizeof(Account) * theContractState.allocated_account_array_size);

  return sizeof(Account) * theContractState.allocated_account_array_size;
}

static unsigned int writeAllowanceArrayToState(unsigned char* buffer,
                                               unsigned int offset) {
  unsigned int written_bytes = 0;
  for (int i = 0; i < theContractState.allocated_allowance_array_size; i++) {
    memcpy(buffer + offset + written_bytes, &globalAllowanceArray[i],
           sizeof(Allowance));
    written_bytes += sizeof(Allowance);
    if (i <= theContractState.num_allowance) {
      memcpy(buffer + offset + written_bytes, globalAllowanceArray[i].records,
             sizeof(AllowanceRecord) *
                 globalAllowanceArray[i].allocated_array_size);
                 
      written_bytes += sizeof(AllowanceRecord) *
                       globalAllowanceArray[i].allocated_array_size;
      free(globalAllowanceArray[i].records);
    }
  }

  return written_bytes;
}

static unsigned int writeBlocksArray(unsigned char* buffer,
                                     unsigned int offset) {
  unsigned int written_bytes = 0;
  for (int i = 0; i < theContractState.allocated_blocks_array_size; i++) {
    memcpy(buffer + offset + written_bytes, &aBlocks[i], sizeof(Block));
    written_bytes += sizeof(Block);
    if (i <= theContractState.num_blocks) {
      memcpy(buffer + offset + written_bytes, aBlocks[i].blockSavers,
             sizeof(int) * aBlocks[i].allocated_blockSavers_size);
      written_bytes += sizeof(int) * aBlocks[i].allocated_blockSavers_size;
      
      memcpy(buffer + offset + written_bytes, aBlocks[i].array_proof_block,
             sizeof(ProofBlock) * aBlocks[i].allocated_array_proof_size);
      written_bytes +=
          sizeof(ProofBlock) * aBlocks[i].allocated_array_proof_size;
      // err_printf("proof Block pos:%x\n",aBlocks[i].array_proof_block);

      
    }
  }

  return written_bytes;
}
static unsigned int writeIpfsNodeArray(unsigned char* buffer,
                                       unsigned int offset) {
  memcpy(buffer + offset, aIpfsNode,
         sizeof(IPFSNode) * theContractState.allocated_ipfsnode_array_size);

  return sizeof(IPFSNode) * theContractState.allocated_ipfsnode_array_size;
}

static unsigned int compute_contract_size() {
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

/*
    Following is an example of the way to create / get your data
    Because C does not have mapping, you may have to use 2-D array to store
   balance
*/

static void initAccountArray() {
  globalAccountArray = malloc(sizeof(Account) * INIT_ACCOUNT_ARRAY_SIZE);
  globalAccountArray[0] = createAccount(ourToken.contractOwnerAddress);
  globalAccountArray[0].balance = ourToken.totalSupply;

  theContractState.allocated_account_array_size = INIT_ACCOUNT_ARRAY_SIZE;
  theContractState.num_account = 1;
  return;
}

static Account* findAccount(char* address) {
  for (int i = 0; i < theContractState.num_account; i++) {
    if (!strcmp(globalAccountArray[i].address, address)) {
      return &globalAccountArray[i];
    }
  }

  return NULL;
}

static Account createAccount(char* address) {
  Account account;

  strcpy(account.address, address);
  account.balance = 0;
  return account;
}

static void appendToAccountArray(Account account) {
  if (theContractState.num_account <
      theContractState.allocated_account_array_size) {
    globalAccountArray[theContractState.num_account] = account;
    theContractState.num_account++;
  } else {
    // re-allocate a bigger array
    int new_allocated_account_array_size =
        theContractState.allocated_account_array_size * 2;
    Account* newAccountArray =
        malloc(sizeof(Account) * new_allocated_account_array_size);

    for (int i = 0; i < theContractState.allocated_account_array_size; i++) {
      newAccountArray[i] = globalAccountArray[i];
    }

    globalAccountArray = newAccountArray;

    globalAccountArray[theContractState.num_account] = account;
    theContractState.num_account++;
    theContractState.allocated_account_array_size =
        new_allocated_account_array_size;
  }

  return;
}

static void initAllowanceArray() {
  globalAllowanceArray = malloc(sizeof(Allowance) * INIT_ALLOWANCE_ARRAY_SIZE);
  globalAllowanceArray[0] = createAllowance(&globalAccountArray[0]);

  theContractState.num_allowance = 1;
  theContractState.allocated_allowance_array_size = INIT_ALLOWANCE_ARRAY_SIZE;
  return;
}

static Allowance createAllowance(Account* account) {
  Allowance allowance;

  strcpy(allowance.allownace_owner_address, account->address);
  allowance.record_count = 0;
  allowance.records =
      malloc(sizeof(AllowanceRecord) * INIT_ALLOWANCE_RECORD_ARRAY_SIZE);
  allowance.allocated_array_size = INIT_ALLOWANCE_RECORD_ARRAY_SIZE;

  return allowance;
}

static Allowance* findAllowance(Account* account) {
  for (int i = 0; i < theContractState.num_allowance; i++) {
    if (!strcmp(globalAllowanceArray[i].allownace_owner_address,
                account->address)) {
      return &globalAllowanceArray[i];
    }
  }

  return NULL;
}

static void appendToAllowanceArray(Allowance target_allowance) {
  if (theContractState.num_allowance <
      theContractState.allocated_allowance_array_size) {
    globalAllowanceArray[theContractState.num_allowance] = target_allowance;
    theContractState.num_allowance++;
  } else {
    // re-allocate a bigger array
    int new_allocated_allowance_array_size =
        theContractState.allocated_allowance_array_size * 2;
    Allowance* newAllowanceArray =
        malloc(sizeof(Allowance) * new_allocated_allowance_array_size);

    for (int i = 0; i < theContractState.allocated_allowance_array_size; i++) {
      newAllowanceArray[i] = globalAllowanceArray[i];
    }

    globalAllowanceArray = newAllowanceArray;

    globalAllowanceArray[theContractState.num_allowance] = target_allowance;
    theContractState.num_allowance++;
    theContractState.allocated_allowance_array_size =
        new_allocated_allowance_array_size;
  }

  return;
}

static AllowanceRecord* findAllowanceRecord(Allowance* target_allowance,
                                            Account* spender_account) {
  for (int i = 0; i < target_allowance->record_count; i++) {
    if (!strcmp(target_allowance->records[i].spender_address,
                spender_account->address)) {
      return &target_allowance->records[i];
    }
  }

  return NULL;
}

static AllowanceRecord createAllowanceRecord(Account* account, int amount) {
  AllowanceRecord record;

  record.amount = amount;
  strcpy(record.spender_address, account->address);

  return record;
}

static void appendToAllowanceRecordArray(Allowance* target_allowance,
                                         AllowanceRecord record) {
  if (target_allowance->record_count < target_allowance->allocated_array_size) {
    target_allowance->records[target_allowance->record_count] = record;
    target_allowance->record_count++;
  } else {
    // re-allocate to bigger array
    int new_allocated_array_size = target_allowance->allocated_array_size * 2;
    AllowanceRecord* new_records =
        malloc(sizeof(AllowanceRecord) * new_allocated_array_size);

    for (int i = 0; i < target_allowance->allocated_array_size; i++) {
      new_records[i] = target_allowance->records[i];
    }

    target_allowance->records = new_records;

    target_allowance->records[target_allowance->record_count] = record;
    target_allowance->record_count++;
    target_allowance->allocated_array_size = new_allocated_array_size;
  }

  return;
}

static void initIpfsArray() {
  aIpfsNode = malloc(sizeof(IPFSNode) * INIT_IPFSNODE_ARRAY_SIZE);

  theContractState.num_ipfsnode = 0;
  theContractState.allocated_ipfsnode_array_size = INIT_IPFSNODE_ARRAY_SIZE;
  return;
}

static int findIPFSnode(char* address) {
  int i = 0;
  for (i = 0; i < theContractState.num_ipfsnode; ++i) {
    err_printf("cmpIPFS:%s,%s\n", aIpfsNode[i].address, address);
    if (!strcmp(aIpfsNode[i].address, address)) {
      return i;
    }
  }
  return -1;
}

static IPFSNode createIpfsNode(char* address, char* ip) {
  IPFSNode ipfsnode;
  strcpy(ipfsnode.address, address);
  strcpy(ipfsnode.ip, ip);
  ipfsnode.available = 1;
  ipfsnode.nBlockNum = 0;
  ipfsnode.tokenAccount = createAccount(address);
  appendToAccountArray(ipfsnode.tokenAccount);
  return ipfsnode;
}

static void appendToIpfsArray(IPFSNode cIpfsNode) {
  if (theContractState.num_ipfsnode <
      theContractState.allocated_ipfsnode_array_size) {
    aIpfsNode[theContractState.num_ipfsnode++] = cIpfsNode;
  } else {
    // re-allocate a bigger array
    int new_allocated_ipfsnode_array_size =
        theContractState.allocated_ipfsnode_array_size * 2;
    IPFSNode* newIpfsNodeArray =
        malloc(sizeof(IPFSNode) * new_allocated_ipfsnode_array_size);

    for (int i = 0; i < theContractState.allocated_ipfsnode_array_size; i++) {
      newIpfsNodeArray[i] = aIpfsNode[i];
    }

    aIpfsNode = newIpfsNodeArray;

    aIpfsNode[theContractState.num_ipfsnode] = cIpfsNode;
    theContractState.num_ipfsnode++;
    theContractState.allocated_ipfsnode_array_size =
        new_allocated_ipfsnode_array_size;
  }
}

static void releaseBlocksArray(Block* oldBlock) {
  for (int i = 0; i < theContractState.num_blocks; ++i) {
    free(oldBlock[i].blockSavers);
    free(oldBlock[i].array_proof_block);
  }
  free(oldBlock);
}

static void initBlockArray() {
  aBlocks = malloc(sizeof(Block) * INIT_BLOCK_ARRAY_SIZE);

  theContractState.num_blocks = 0;
  theContractState.allocated_blocks_array_size = INIT_IPFSNODE_ARRAY_SIZE;
  return;
}

static void appendToBlockArray(Block block) {
  if (theContractState.num_blocks <
      theContractState.allocated_blocks_array_size) {
    aBlocks[theContractState.num_blocks++] = block;
  } else {
    // re-allocate a bigger array
    int new_allocated_blocks_array_size =
        theContractState.allocated_blocks_array_size * 2;
    Block* newBlocksArray =
        malloc(sizeof(Block) * new_allocated_blocks_array_size);

    for (int i = 0; i < theContractState.allocated_blocks_array_size; i++) {
      newBlocksArray[i] = aBlocks[i];
    }
    free(aBlocks);
    aBlocks = newBlocksArray;

    aBlocks[theContractState.num_blocks] = block;
    theContractState.num_blocks++;
    theContractState.allocated_blocks_array_size =
        new_allocated_blocks_array_size;
  }
}

static void appendToBlockSaverArray(int* psaver, int index_saver,
                                    int* allocated_saver_array_size,
                                    int* num_saver) {
  if (!((*num_saver) < (*allocated_saver_array_size))) {
    int new_allocated_saver_array_size = *allocated_saver_array_size * 2;
    int* newSaverArray = malloc(sizeof(int) * new_allocated_saver_array_size);
    for (int i = 0; i < *allocated_saver_array_size; i++) {
      newSaverArray[i] = psaver[i];
    }
    free(psaver);
    psaver = newSaverArray;
    *allocated_saver_array_size = new_allocated_saver_array_size;
  }
  psaver[(*num_saver)++] = index_saver;
}

static void appendToProofArray(ProofBlock* proofList, ProofBlock proof,
                               int* allocated_proof_array_size,
                               int* num_proof) {
  if (!((*num_proof) < (*allocated_proof_array_size))) {
    int new_allocated_saver_array_size = *allocated_proof_array_size * 2;
    ProofBlock* newSaverArray =
        malloc(sizeof(ProofBlock) * new_allocated_saver_array_size);
    for (int i = 0; i < *allocated_proof_array_size; i++) {
      newSaverArray[i] = proofList[i];
    }
    free(proofList);
    proofList=NULL;
    proofList = newSaverArray;
    *allocated_proof_array_size = new_allocated_saver_array_size;
  }
  proofList[(*num_proof)++] = proof;
}

/**
 * @brief connect with IPFS
 *
 * @param path
 * @param n_path
 * @return char*
 */
char* HTTPrequest(char* path, int n_path) {
  // err_printf("HTTPRequest\n");
  char* host = "127.0.0.1";  // 目標 URI
  char* PORT_NUM = "5001";   // HTTP port

  char request[0xfff], response[0xfff];  // 請求 與 回應訊息
  char* requestLine = malloc(21 + n_path + 11);
  sprintf(requestLine, "POST /api/v0/cat?arg=%s HTTP/1.1\r\n", path);  // 請求行
  char* headerFmt = "Host: %s\r\n";  // Host 表頭欄位
  char* CRLF = "\r\n";               // 表頭後的 CRLF

  int cfd;                // Socket 檔案描述符 (File Descriptor)
  int gaiStatus;          // getaddrinfo 狀態碼
  struct addrinfo hints;  // hints 參數，設定 getaddrinfo() 的回傳方式
  struct addrinfo* result;  // getaddrinfo() 執行結果的 addrinfo 結構指標

  // 動態配置記憶體，以決定 表頭緩衝區 (Header Buffer) 長度
  size_t bufferLen = strlen(headerFmt) + strlen(host) + 1;
  char* buffer = (char*)malloc(bufferLen);  // 表頭緩衝區

  //組裝請求訊息
  strcpy(request, requestLine);
  snprintf(buffer, bufferLen, headerFmt, host);
  strcat(request, buffer);
  strcat(request, CRLF);

  // 釋放緩衝區記憶體
  free(buffer);
  // free(requestLine);

  // free(CRLF);
  // free(headerFmt);
  buffer = NULL;

  // 以 memset 清空 hints 結構
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;      // 使用 IPv4 or IPv6
  hints.ai_socktype = SOCK_STREAM;  // 串流 Socket
  hints.ai_flags =
      AI_NUMERICSERV;  // 將 getaddrinfo() 第 2 參數 (PORT_NUM) 視為數字

  // 以 getaddrinfo 透過 DNS，取得 addrinfo 鏈結串列 (Linked List)
  // 以從中取得 Host 的 IP 位址
  if ((gaiStatus = getaddrinfo(host, PORT_NUM, &hints, &result)) != 0)
    return NULL;

  // 分別以 domain, type, protocol 建立 socket 檔案描述符
  cfd = socket(result->ai_family, result->ai_socktype, 0);

  // 以 socket 檔案描述符 (cfd), addr, addrlen 進行連線
  // 其中，result->ai_addr 為 gai 取得之 通用 socket 位址結構 -- sockaddr
  if (connect(cfd, result->ai_addr, result->ai_addrlen) < 0) return NULL;

  // 釋放 getaddrinfo (Linked List) 記憶體空間
  freeaddrinfo(result);
  result = NULL;

  // 格式化輸出請求訊息
  printf("----------\nRequest:\n----------\n%s\n", request);

  // 發送請求
  if (send(cfd, request, strlen(request), 0) < 0) return NULL;

  // 接收回應
  if (recv(cfd, response, 0xfff, 0) < 0) return NULL;

  // 格式化輸出回應訊息
  printf("----------\nResponse:\n----------\n%s\n", response);

  char* token;

  const char split[] = "\r\n";
  int index = 0;
  char* res;
  token = strtok(response, split);

  while (token != NULL) {
    printf("%d: %s\n", index++, token);
    if (index - 1 == 12) {
      printf("size of token: %d\n", strlen(token));
      res = malloc(strlen(token));
      memcpy(res, token, strlen(token));
    }
    token = strtok(NULL, split);
  }
  // free(token);

  printf("source: %s\n", res);
  // 半雙工關閉 TCP Socket 連線
  // (i.e., 關閉寫入)
  shutdown(cfd, SHUT_WR);
  // free(host);
  // free(PORT_NUM);
  // err_printf("res:%s\n",res);
  return res;

}  // TODO: Write testing code to run=[-]

unsigned int charVal(char i) {
  return (i >= '0' && i <= '9') ? i - '0' : i - 'a' + 10;
}

/**
 * @brief convert string to hex
 *
 * @param from
 * @param nFrom
 * @return unsigned*
 */
unsigned char* StrHex(char* from, int nFrom) {
  unsigned char* result = malloc(nFrom / 2);
  int index = 0;
  for (int i = 0; i < nFrom; i += 2) {
    unsigned char val = charVal(from[i]);
    val <<= 4;
    val += charVal(from[i + 1]);
    result[index++] = val;
  }
  return result;
}

CPOR_proof* UnserializeProof(unsigned char* pfrom) {
  unsigned int offset = 0;
  CPOR_proof* newProof = allocate_cpor_proof();

  int bigNumSize;
  memcpy(&bigNumSize, pfrom + offset, sizeof(int));
  offset += sizeof(int);

  unsigned char* sigma_char = malloc(bigNumSize);
  memcpy(sigma_char, pfrom + offset, bigNumSize);
  BN_bin2bn(sigma_char, bigNumSize, newProof->sigma);
  offset += bigNumSize;

  for (int i = 0; i < params.num_sectors; ++i) {
    int newNum;
    memcpy(&newNum, pfrom + offset, sizeof(int));
    offset += sizeof(int);

    unsigned char* mu_char = malloc(newNum);
    memcpy(mu_char, pfrom + offset, newNum);
    BN_bin2bn(mu_char, newNum, newProof->mu[i]);
    offset += newNum;
    free(mu_char);
  }
  free(sigma_char);
  return newProof;
}

CPOR_challenge* UnserializeChallenge(unsigned char* pfrom) {
  unsigned char* zp_char;
  unsigned int offset = 0;

  unsigned int l;
  unsigned int I;
  int zp_size;

  memcpy(&l, pfrom, sizeof(unsigned int));
  offset += sizeof(unsigned int);

  CPOR_challenge* newChallenge = allocate_cpor_challenge(l);
  newChallenge->l = l;

  for (int i = 0; i < newChallenge->l; ++i) {
    memcpy(&I, pfrom + offset, sizeof(unsigned int));
    newChallenge->I[i] = I;
    offset += sizeof(unsigned int);
  }

  memcpy(&zp_size, pfrom + offset, sizeof(int));
  zp_char = malloc(zp_size);

  offset += sizeof(int);

  memcpy(zp_char, pfrom + offset, zp_size);
  BN_bin2bn(zp_char, zp_size, newChallenge->global->Zp);
  offset += zp_size;
  for (int i = 0; i < newChallenge->l; ++i) {
    int bigNumSize;
    memcpy(&bigNumSize, pfrom + offset, sizeof(int));
    offset += sizeof(int);

    unsigned char* nu_char = malloc(bigNumSize);
    memcpy(nu_char, pfrom + offset, bigNumSize);
    BN_bin2bn(nu_char, bigNumSize, newChallenge->nu[i]);
    offset += bigNumSize;
    free(nu_char);
  }
  free(zp_char);
  return newChallenge;
}

CPOR_t* UnserializeT(unsigned char* pfrom) {
  unsigned int offset = 0;

  CPOR_t* t = allocate_cpor_t();

  memcpy(&t->n, pfrom, sizeof(unsigned int));
  offset += sizeof(unsigned int);

  memcpy(t->k_prf, pfrom + offset, params.prf_key_size);
  offset += params.prf_key_size;

  for (int i = 0; i < params.num_sectors; ++i) {
    int nSize;
    memcpy(&nSize, pfrom + offset, sizeof(int));
    offset += sizeof(int);

    unsigned char* alpha_char = malloc(nSize);
    memcpy(alpha_char, pfrom + offset, nSize);
    BN_bin2bn(alpha_char, nSize, t->alpha[i]);
    offset += nSize;
    free(alpha_char);
  }
  return t;
}

void hexPrintf(unsigned char* hex, int n) {
  err_printf("--------------Hex--------------\n");
  for (int i = 0; i < n; ++i) {
    err_printf("%2x ", hex[i]);
  }
  err_printf("-------------Hex END-----------\n");
}

/**
 * @brief Validate the saving status
 *
 * @param proofCID
 * @param challengeCID
 * @param block
 * @return int
 */
int validateProof(char* proofCID, char* challengeCID, Block* block) {
  // char* source = HTTPrequest("POST","","");//read proof from IPFS
  // char* blockPath = "";// 讀取本地的區塊用來驗證
  char* proof_ret = HTTPrequest(proofCID, strlen(proofCID));
  unsigned char* proof_hex = StrHex(proof_ret, strlen(proof_ret));
  // err_printf("proof: %s\n",proof_ret);
  // hexPrintf(proof_hex, strlen(proof_ret));
  char* challenge_ret = HTTPrequest(challengeCID, strlen(challengeCID));
  unsigned char* challenge_hex = StrHex(challenge_ret, strlen(challenge_ret));
  // err_printf("challenge_ret: %s\n",challenge_ret);
  // hexPrintf(challenge_hex, strlen(challenge_ret));
  char* tfile_ret = HTTPrequest(block->tfileCID, strlen(block->tfileCID));
  unsigned char* tfile_hex = StrHex(tfile_ret, strlen(tfile_ret));
  // err_printf("tfile_ret: %s\n",tfile_ret);
  // hexPrintf(tfile_hex, strlen(tfile_ret));

  CPOR_proof* proof = UnserializeProof(proof_hex);
  CPOR_challenge* challenge =
      UnserializeChallenge(StrHex(challenge_ret, strlen(challenge_ret)));
  CPOR_t* t = UnserializeT(StrHex(tfile_ret, strlen(tfile_ret)));
  int ret = cpor_verify_proof(challenge->global, proof, challenge, t->k_prf,
                              t->alpha);
  destroy_cpor_challenge(challenge);
  destroy_cpor_proof(proof);
  destroy_cpor_t(t);
  free(proof_ret);
  free(challenge_ret);
  free(tfile_ret);
  free(proof_hex);
  free(challenge_hex);
  free(tfile_hex);
  err_printf("Validate Proof: %d\n", ret);
  return ret;
}

int cmpIPFSNode(IPFSNode* node1, IPFSNode* node2) {
  if (!strcmp(node1->address, node2->address)) return 1;
  return 0;
}

static int user_sign_up(char* address, char* ip) {
  if (findIPFSnode(address) == -1) {
    appendToIpfsArray(createIpfsNode(address, ip));
    return theContractState.num_ipfsnode - 1;
  } else {
    return -1;
  }
}

int findBlock(char* merkle_root) {
  int i = 0;
  for (i = 0; i < theContractState.num_blocks; ++i) {
    if (!strcmp(merkle_root, aBlocks[i].merkleRoot)) return i;
  }
  return -1;
}

int findBlockSaver(int index, int index_IpfsNode) {
  int i = 0;
  for (i = 0; i < aBlocks[index].nBlockSavers; ++i) {
    if (aBlocks[index].blockSavers[i] == index_IpfsNode) return i;
  }
  return 0;
}

Block* createBlock() {
  Block* nowBlock = malloc(sizeof(Block));
  nowBlock->nBlockSavers = 0;
  nowBlock->num_proof = 0;
  nowBlock->allocated_array_proof_size = INIT_PROOF_ARRAY_SIZE;
  nowBlock->num_proof = 0;
  nowBlock->array_proof_block =
      malloc(sizeof(ProofBlock) * nowBlock->allocated_array_proof_size);
  nowBlock->allocated_blockSavers_size = INIT_IPFSNODE_ARRAY_SIZE;
  nowBlock->blockSavers =
      malloc(sizeof(int) * nowBlock->allocated_blockSavers_size);
  return nowBlock;
}

int cmpIPFSnodeBlockNum(const void* a, const void* b) {
  return ((IPFSNode*)a)->nBlockNum - ((IPFSNode*)b)->nBlockNum;
}

void qsortIPFS(IPFSNode* pIpfsnode, size_t nItems) {
  qsort(pIpfsnode, nItems, sizeof(IPFSNode), cmpIPFSnodeBlockNum);
}

/**
 * @brief This function is used to those ipfs nodes who stored their file by
 * contract pricing strategy.
 *
 * @param merkle_root
 * @param CID
 * @param index_Ipfsnode
 * @param tfileCID
 * @param tagCID
 * @param time
 * @return int
 */
static int saveBlockByDynamic(char* merkle_root, char* CID, int index_Ipfsnode,
                              int time) {
  IPFSNode* pIpfsNode = &aIpfsNode[index_Ipfsnode];
  int blockIndex = findBlock(merkle_root);
  Block* nowBlock;
  err_printf("blockIndex: %d\n", blockIndex);
  if (blockIndex > -1) {
    // Check if ipfsNode exist in the blocksaver
    int res = findBlockSaver(blockIndex, pIpfsNode);
    if (res) return -1;
    nowBlock = &aBlocks[blockIndex];

  } else {
    return -1;
  }

  /**
   * @brief Because the file is not delpoy by user directly,
   * ipfs only need to store and will be challenged next time.
   *
   */
  appendToBlockSaverArray(nowBlock->blockSavers, index_Ipfsnode,
                          &nowBlock->allocated_blockSavers_size,
                          &nowBlock->nBlockSavers);
  // nowBlock->blockSavers[nowBlock->nBlockSavers] = index_Ipfsnode;
  pIpfsNode->nBlockNum++;

  if (blockIndex == -1) {
    appendToBlockArray(*nowBlock);
    // TODO: 0419blockIndex do not append
    blockIndex = theContractState.num_blocks;
  }

  return blockIndex;
}
/**
 * @brief This function is used to store the block which deploy by
 * default.
 *
 * @param merkle_root
 * @param CID
 * @param index_Ipfsnode
 * @param proofCID
 * @param time
 * @param challengCID
 * @param tfileCID
 * @param tagCID
 * @return int
 */
static int saveBlockByDefault(char* merkle_root, char* CID, int index_Ipfsnode,
                              char* proofCID, int time, char* challengCID,
                              char* tfileCID, char* tagCID) {
  IPFSNode* pIpfsNode = &aIpfsNode[index_Ipfsnode];
  int blockIndex = findBlock(merkle_root);
  Block* nowBlock;
  int newFlag = 0;
  err_printf("blockIndex: %d\n", blockIndex);
  if (blockIndex > -1) {
    // Check if ipfsNode exist in the blocksaver
    int res = findBlockSaver(blockIndex, pIpfsNode);
    if (res) return -1;
    nowBlock = &aBlocks[blockIndex];
    if (strcmp(tfileCID, nowBlock->tfileCID)) {
      return -1;
    }

  } else {
    // Create the initial block
    nowBlock = createBlock();
    strcpy(nowBlock->merkleRoot, merkle_root);
    strcpy(nowBlock->CIDHash, CID);
    strcpy(nowBlock->tfileCID, tfileCID);
    strcpy(nowBlock->tagCID, tagCID);
    newFlag = 1;
  }

  /**
   * @brief Validate the proof to prevent the fake upload
   *
   */
  int ret = validateProof(proofCID, challengCID, nowBlock);
  if (!ret){
    if(newFlag){
      releaseBlocksArray(nowBlock);
    }
    return -1;
  } 

  appendToBlockSaverArray(nowBlock->blockSavers, index_Ipfsnode,
                          &nowBlock->allocated_blockSavers_size,
                          &nowBlock->nBlockSavers);
  // nowBlock->blockSavers[nowBlock->nBlockSavers] = index_Ipfsnode;
  pIpfsNode->nBlockNum++;

  ProofBlock* proofBlock = malloc(sizeof(ProofBlock));

  strcpy(proofBlock->cChallengeCIDHash, challengCID);
  strcpy(proofBlock->cCIDHash, CID);
  appendToProofArray(nowBlock->array_proof_block, *proofBlock,
                     &nowBlock->allocated_array_proof_size,
                     &nowBlock->num_proof);
  free(proofBlock);

  // free(proofBlock);
  // err_printf("proof Block pos:%x\n",nowBlock->array_proof_block);
  if (blockIndex == -1) {
    appendToBlockArray(*nowBlock);
    // releaseBlocksArray(nowBlock);
    free(nowBlock); 
    // TODO: 0419blockIndex do not append
    blockIndex = theContractState.num_blocks;
  }
  
  return blockIndex;
}

static int saveProof(char* merkle_root, char* proofCID, char* challengeCID,
                     IPFSNode* cIpfsnode, time_t time) {
  ProofBlock* cProofBlock = malloc(sizeof(ProofBlock));

  Block* cblock = &aBlocks[findBlock(merkle_root)];
  int ret = validateProof(proofCID, challengeCID, cblock);
  if (!ret) return -1;
  strcpy(cProofBlock->cAddress, cIpfsnode->address);
  strcpy(cProofBlock->cCIDHash, proofCID);
  cProofBlock->time = time;

  // cblock->array_proof_block[cblock->num_proof] = *cProofBlock;
  appendToProofArray(cblock->array_proof_block, *cProofBlock,
                     &cblock->allocated_array_proof_size, &cblock->num_proof);
  // free(cblock);
  free(cProofBlock);
  return 1;
}

static int removeBlockSaver(char* merkle_root, int index_ipfs) {
  int ret = findBlock(merkle_root);
  if (ret == -1) return -1;
  Block* nowBlock = &aBlocks[ret];
  int* newBlockSaver =
      malloc(sizeof(int) * nowBlock->allocated_blockSavers_size);
  int index = 0;
  for (int i = 0; i < nowBlock->nBlockSavers; ++i) {
    if (nowBlock->blockSavers[i] != index_ipfs) {
      newBlockSaver[index++] = nowBlock->blockSavers[i];
    }
  }
  nowBlock->blockSavers = newBlockSaver;
  return 1;
}

static int repair(char* merkle_root, IPFSNode* misbehabiorNode) {
  Block* pblock = &aBlocks[findBlock(merkle_root)];

  IPFSNode* pRepairNode =
      malloc(sizeof(IPFSNode) * theContractState.num_replication);
  // order the least storing node to repair
  //  qsortIPFS(state->aSignList,)
}

static void printAllBlock() {
  err_printf("All Block, Num: %d\n", theContractState.num_blocks);
  for (int i = 0; i < theContractState.num_blocks; ++i) {
    err_printf("Merkle Root: %s, CID hash: %s\n", aBlocks[i].merkleRoot,
               aBlocks[i].CIDHash);
  }
}

static void initParams() {
  /* Set default parameters */
  params.lambda = 80; /* The security parameter lambda */

  params.prf_key_size = 20; /* Size (in bytes) of an HMAC-SHA1 */
  params.enc_key_size =
      32; /* Size (in bytes) of the user's AES encryption key */
  params.mac_key_size = 20; /* Size (in bytes) of the user's MAC key */

  params.block_size = 100; /* Message block size in bytes */
  params.num_threads = 4;
  params.num_challenge =
      params.lambda; /* From the paper, a "conservative choice" for l is lamda,
                        the number of bits to represent our group, Zp */

  params.filename = NULL;
  params.filename_len = 0;

  params.op = CPOR_OP_NOOP;

  /* The size (in bits) of the prime that creates the field Z_p */
  params.Zp_bits = params.lambda;
  /* The message sector size 1 byte smaller than the size of Zp so that it
   * is guaranteed to be an element of the group Zp */
  params.sector_size = ((params.Zp_bits / 8) - 1);
  /* Number of sectors per block */
  params.num_sectors = ((params.block_size / params.sector_size) +
                        ((params.block_size % params.sector_size) ? 1 : 0));
}

int contract_main(int argc, char** argv) {
  if (argc < 2) {
    // too_few_args();
    return -1;
  }
  initParams();
  if (!strcmp(argv[1], CONTRACT_INIT_FUNC)) {
    err_printf("init contract\n");

    // contract-related data
    strcpy(ourToken.contractOwnerAddress, INIT_ADDR);
    strcpy(ourToken.name, "IPFSToken");
    strcpy(ourToken.symbol, "ITK");
    ourToken.decimal = 1;
    ourToken.totalSupply = 1e9;

    // contract-state data
    err_printf("Initial Account Array\n");
    initAccountArray();
    err_printf("initAllowanceArray()\n");
    initAllowanceArray();
    err_printf("initIpfsArray()\n");
    initIpfsArray();
    err_printf("initBlockArray()\n");
    initBlockArray();
    err_printf("compute_contract_size()\n");
    theContractState.size_contract = compute_contract_size();
    theContractState.num_replication = 3;

    writeState();
  } else {
    readState();

    if (!strcmp(argv[1], "symbol")) {
      err_printf("symbol:%s\n", symbol());
    } else if (!strcmp(argv[1], "name")) {
      err_printf("name:%s\n", name());
    } else if (!strcmp(argv[1], "decimal")) {
      err_printf("decimals:%d\n", decimals());
    } else if (!strcmp(argv[1], "totalSupply")) {
      err_printf("totalSuply:%d\n", totalSupply());
    } else if (!strcmp(argv[1], "user_sign_up")) {
      if (argc != 4) {
        err_printf("%s: usage: sfc2 user_sign_up user_address ip_address\n",
                   argv[0]);
        return -1;
      }
      err_printf("userSignUp:%d\n", user_sign_up(argv[2], argv[3]));
    } else if (!strcmp(argv[1], "balanceOf")) {
      if (argc < 3) {
        err_printf("%s: usage: scf2 balanceOf user_address\n", argv[0]);
        return -1;
      }
      err_printf("balanceOf %s:%d\n", argv[2], balanceOf(argv[2]));
    } else if (!strcmp(argv[1], "allowance")) {
      if (argc < 4) {
        err_printf(
            "%s: usage: scf2 allowance token_owner_address spender_address\n",
            argv[0]);
        return -1;
      }
      err_printf("allowance:%d\n", allowance(argv[2], argv[3]));
    } else if (!strcmp(argv[1], "proof_block")) {
      /*
       * argv[2]: merkle root
       * argv[3]: ipfs pubkey
       * argv[4]: proof CID
       * argv[5]: challenge CID
       * argv[6]: time
       */
      if (argc != 7) return -1;
      int n_ipfs_index = findIPFSnode(argv[3]);
      err_printf("index:%d\n", n_ipfs_index);
      if (n_ipfs_index < 0) return -1;
      int ret = saveProof(argv[2], argv[4], argv[5], &aIpfsNode[n_ipfs_index],
                          argv[6]);
      err_printf("Proof:%d,%s,%s,%s\n", ret, argv[2], argv[3], argv[4]);
      if (ret < 0) return -1;
      // out_clear();
      out_printf("Proof: %d,%s,%s,%s\n", ret, argv[2], argv[3], argv[6]);

    } else if (!strcmp(argv[1], "proof_blocks")) {
      /*
       * argv[2]: ipfs pubkey
       * argv[n]: merkle root
       * argv[n + 1]: proof CID
       * argv[n + 2]: challenge CID
       * argv[n + 3]: time
       */
      int n_ipfs_index = findIPFSnode(argv[2]);
      err_printf("index:%d\n", n_ipfs_index);
      if (n_ipfs_index < 0) return -1;
      for (int i = 3; i + 3 < argc; i += 4) {
        int ret = saveProof(argv[i], argv[i + 1], argv[i + 2],
                            &aIpfsNode[n_ipfs_index], atoi(argv[i + 3]));
        err_printf("Proofs:%d,%s,%s,%s,%s\n", ret, argv[i], argv[i + 1],
                   argv[i + 2], argv[i + 3]);
        if (ret > 0) {
          out_printf("Proofs:%d,%s,%s,%s,%s,%s\n", ret, argv[i], argv[i + 1],
                     argv[i + 2], argv[i + 3], time(NULL));
        }
        // out_clear();
      }

    } else if (!strcmp(argv[1], "save_block")) {
      /**
       * Argc num = 10
       * argv[2]: merkle root
       * argv[3]: CID
       * argv[4]: ipfs pubkey
       * argv[5]: proof CID
       * argv[6]: tfileCID
       * argv[7]: challenge CID
       * argv[8]: TagCID
       * argv[9]: time
       *
       * Argc num = 6
       * argv[2]: merkle root
       * argv[3]: CID
       * argv[4]: ipfs pubkey
       * argv[5]: time
       */
      // if (!(argc == 6 || argc == 10)) return -1;
      err_printf("argc num = %d\n", argc);
      int n_ipfs_index = findIPFSnode(argv[4]);
      err_printf("index:%d\n", n_ipfs_index);
      if (n_ipfs_index < 0) return -1;
      int ret = -1;
      if (argc == 10) {
        ret = saveBlockByDefault(argv[2], argv[3], n_ipfs_index, argv[5],
                                 atoi(argv[9]), argv[7], argv[6], argv[8]);
      } else {
        ret = saveBlockByDynamic(argv[2], argv[3], n_ipfs_index, atoi(argv[5]));
      }

      err_printf("%d,%s,%s,%s\n", ret, argv[2], argv[3], argv[4]);
      if (ret < 0) return -1;
      // out_clear();
      out_printf("SaveBlock: %d,%s,%s,%s,%d\n", ret, argv[2], argv[3], argv[4],
                 time(NULL));

    } else if (!strcmp(argv[1], "save_blocks")) {
      /**
       * Argc num = X
       * argv[2]: ipfs pubkey
       * argv[3]: numbers
       * argv[n]: merkle root
       * argv[n+1]: CID
       * argv[n+2]: proof CID
       * argv[n+3]: tfileCID
       * argv[n+4]: challenge CID
       * argv[n+5]: TagCID
       * argv[n+6]: time
       *
       * Argc num = 6
       * argv[2]: merkle root
       * argv[3]: CID
       * argv[4]: ipfs pubkey
       * argv[5]: time
       */
      int n_ipfs_index = findIPFSnode(argv[2]);
      err_printf("index:%d\n", n_ipfs_index);
      if (n_ipfs_index < 0) return -1;
      for (int i = 4; i + 6 < argc; i += 7) {
        err_printf("SaveBlocks: %s,%s,%s,%s,%s,%s,%s\n", argv[i], argv[i + 1],
                   argv[i + 2], argv[i + 3], argv[i + 4], argv[i + 5],
                   argv[i + 6]);
        int ret = saveBlockByDefault(argv[i], argv[i + 1], n_ipfs_index,
                                     argv[i + 2], atoi(argv[i + 6]),
                                     argv[i + 4], argv[i + 3], argv[i + 5]);
        err_printf("ret: %d\n", ret);
        if (ret > 0) {
          // out_clear();
          out_printf("SaveBlocks: %d,%s,%s,%s,%d\n", ret, argv[2], argv[3],
                     argv[4], time(NULL));
        }
      }

    } else if (!strcmp(argv[1], "dynamic_save_blocks")) {
      /**
       * Argc num = X
       * argv[2]: ipfs pubkey
       * argv[3]: numbers
       * argv[n]: merkle root
       * argv[n+1]: CID
       * argv[n+2]: time
       */
      int n_ipfs_index = findIPFSnode(argv[2]);
      err_printf("index:%d\n", n_ipfs_index);
      for (int i = 4; i + 2 < argc; i += 3) {
        err_printf("DynamicSaveBlocks: %s,%s,%s,%s,%s,%s,%s", argv[i],
                   argv[i + 1], argv[i + 2]);
        int ret = saveBlockByDynamic(argv[i], argv[i + 1], n_ipfs_index,
                                     atoi(argv[i + 2]));
        err_printf("ret: %d\n", ret);
        if (ret < 0) {
          // out_clear();
          out_printf("DynamicSaveBlocks: %s,%s,%s,%s,%s,%s,%s", argv[i],
                     argv[i + 1], argv[i + 2]);
        }
      }
    } else if (!strcmp(argv[1], "remove_block")) {
      /**
       * @brief remove_block is to remove saving file annoucement
       * argv[2]: merkle_root
       * argv[3]: ipfs pubkey
       */
      int n_ipfs_index = findIPFSnode(argv[3]);
      err_printf("Remove index:%d\n", n_ipfs_index);
      if (n_ipfs_index < 0) return -1;
      int ret = removeBlockSaver(argv[2], n_ipfs_index);
      err_printf("Remove: %d,%s,%s\n", ret, argv[2], argv[3]);
      out_printf("Remove: %d,%s,%s,%d\n", ret, argv[2], argv[3], time(NULL));
      if (ret < 0) return -1;
    } else if (!strcmp(argv[1], "printAllBlocks")) {
      printAllBlock();
    } else {
      err_printf("error:command not found:%s\n", argv[1]);
      return 0;
    }

    theContractState.size_contract = compute_contract_size();
    writeState();
  }

  return 0;
}
