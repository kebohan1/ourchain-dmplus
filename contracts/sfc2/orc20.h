#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CONTRACT_INIT_FUNC "init"
#define INIT_ACCOUNT_ARRAY_SIZE 20
#define INIT_ALLOWANCE_ARRAY_SIZE 10
#define INIT_ALLOWANCE_RECORD_ARRAY_SIZE 5

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

typedef struct state {
    unsigned int size_contract; 
    unsigned int num_account;
    unsigned int allocated_account_array_size;
    unsigned int num_allowance;
    unsigned int allocated_allowance_array_size;
} ContractState;

/* optional APIs */
char* symbol();
char* name();
int decimals();

/* required APIs */
int totalSupply();
int balanceOf(char*);
int allowance(char*, char*);
int approve(char* ,char*, int);
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

static AllowanceRecord* findAllowanceRecord(Allowance*, Account*);
static AllowanceRecord createAllowanceRecord(Account*, int);
static void appendToAllowanceRecordArray(Allowance*, AllowanceRecord);

//static unsigned int readState();
static unsigned int readContractState(unsigned char*, unsigned int);
static unsigned int readToken(unsigned char*, unsigned int);
static unsigned int readAccountArray(unsigned char*, unsigned int);
static unsigned int readAllowanceArray(unsigned char*, unsigned int);

//static unsigned int writeState();
static unsigned int writeTokenToState(unsigned char*, unsigned int);
static unsigned int writeContractStateToState(unsigned char*, unsigned int);
static unsigned int writeAccountArrayToState(unsigned char*, unsigned int);
static unsigned int writeAllowanceArrayToState(unsigned char*, unsigned int);

static unsigned int compute_contract_size();

Account *globalAccountArray;
Allowance *globalAllowanceArray;
Token ourToken;
ContractState theContractState;

/* 
  Debug functions
  err_printf() will print to regtest/contracts/err
  out_printf() will print to regtest/contracts/<contract_id>/out

  Warning: DO NOT use printf(). Usually it will block your program
*/ 

void print_contract_state()
{
    err_printf("%u,%u,%u,%u,%u\n", theContractState.size_contract,
               theContractState.num_account,
               theContractState.allocated_account_array_size,
               theContractState.num_allowance,
               theContractState.allocated_allowance_array_size);
    return;
}

void print_token()
{
    err_printf("%s,%s,%s,%d,%d\n", ourToken.contractOwnerAddress,
                               ourToken.name,
                               ourToken.symbol,
                               ourToken.decimal,
                               ourToken.totalSupply);
    return;
}

void print_global_account_array()
{
    for (int i = 0; i < theContractState.num_account; i++) {
        err_printf("%s,%d\n", globalAccountArray[i].address, globalAccountArray[i].balance);
    }
    return;
}

void print_global_allowance_array()
{
    for (int i = 0; i < theContractState.num_allowance; i++) {
        err_printf("%s,%d\n", globalAllowanceArray[i].allownace_owner_address, globalAllowanceArray[i].record_count);
        for (int j = 0; j < globalAllowanceArray[i].record_count; j++) {
            err_printf("%s,%d\n", globalAllowanceArray[i].records[j].spender_address, globalAllowanceArray[i].records[j].amount);
        }
    }
    return;
}

void print_sys_args(int argc, char** argv)
{
    for (int i = 0; i < argc; i++) err_printf("%s,", argv[i]);
    err_printf("\n");
    return;
}

/* 
   Implement your ERC20-like functions
*/

char* symbol()
{
    return ourToken.symbol;
}

char* name()
{
    return ourToken.name;
}

int decimals()
{
    return ourToken.decimal;
}

int totalSupply()
{
    return ourToken.totalSupply;
}

int balanceOf(char* requester_address)
{
    Account *requester_account = findAccount(requester_address);

    if (requester_account == NULL) {
        err_printf("%s account not found\n", requester_address);
        return 1;
    }
    return requester_account->balance;
}

int allowance(char* token_owner_address, char* spender_address)
{
    Account* token_owner_account = findAccount(token_owner_address);
    Account* spender_account = findAccount(spender_address);

    if (token_owner_account == NULL) {
        err_printf("%s account not found\n", token_owner_address);
        return -1;
    } else if (spender_account == NULL) {
        err_printf("%s account not found\n", spender_address);
        return -1;
    }

    Allowance* token_owner_allowance = findAllowance(token_owner_account);
    if (token_owner_allowance == NULL) {
        err_printf("%s allowance not found\n", token_owner_address);
        return -1;
    }

    AllowanceRecord* record = findAllowanceRecord(token_owner_allowance, spender_account);
    if (record == NULL) {
        err_printf("%s allowance not found\n", spender_address);
        return -1;
    }

    return record->amount;
}

int approve(char* token_owner_address, char* spender_address, int amount)
{
    if (amount < 0) {
        err_printf("error:amount < 0\n");
        return -1;
    }

    Account* token_owner_account = findAccount(token_owner_address);
    if (token_owner_account == NULL) {
        err_printf("%s account not found\n", token_owner_address);
        return -1;
        //appendToAccountArray(createAccount(token_owner_address));
        //token_owner_account = findAccount(token_owner_address);
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
        //appendToAccountArray(createAccount(spender_address));
        //spender_account = findAccount(spender_address);
    }

    AllowanceRecord* record = findAllowanceRecord(token_owner_allowance, spender_account);
    if (record == NULL) {
        appendToAllowanceRecordArray(token_owner_allowance, createAllowanceRecord(spender_account, amount));
        record = findAllowanceRecord(token_owner_allowance, spender_account);
    } else {
        record->amount = amount;
    }

    return 1;
}

int transfer(char* msg_sender_address, char* to_address ,int amount)
{
    Account* msg_sender_account = findAccount(msg_sender_address);
    if (msg_sender_account == NULL) {
        err_printf("%s account not found\n", msg_sender_address);
        return -1;
    }

    Account* to_account = findAccount(to_address);
    if (to_account == NULL) {
        err_printf("%s account not found\n", to_address);
        return -1;
        //appendToAccountArray(createAccount(to_address));
        //to_account = findAccount(to_address);
    }

    if (msg_sender_account->balance >= amount && amount > 0) {
        to_account->balance += amount;
        msg_sender_account->balance -= amount;
        return 1;
    }

    err_printf("insufficient funds\n");
    return -1;
}

int transferFrom(char* msg_sender_address, char* token_onwer_address, char* to_address, int amount)
{
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
        //appendToAccountArray(createAccount(to_address));
        //to_account = findAccount(to_address);
    }
    
    int allowance_value = allowance(token_onwer_address, msg_sender_address);

    if (token_owner_account->balance >= amount
            && allowance_value >= amount
            && amount > 0) {
        Allowance* token_owner_allowance = findAllowance(token_owner_account);
        AllowanceRecord* record = findAllowanceRecord(token_owner_allowance, msg_sender_account);

        token_owner_account->balance -= amount;
        record->amount -= amount;
        to_account->balance += amount;

        return 1;
    }

    return -1;
}

static unsigned int readContractState(unsigned char* buffer, unsigned int offset)
{
    memcpy(&theContractState, buffer+offset, sizeof(ContractState));
    return sizeof(ContractState);
}

static unsigned int readToken(unsigned char* buffer, unsigned int offset)
{
    memcpy(&ourToken, buffer+offset, sizeof(Token));
    return sizeof(Token);
}

static unsigned int readAccountArray(unsigned char* buffer, unsigned int offset)
{
    globalAccountArray = malloc(sizeof(Account) * theContractState.allocated_account_array_size);
    memcpy(globalAccountArray, buffer+offset, sizeof(Account) * theContractState.allocated_account_array_size);
    return sizeof(Account) * theContractState.allocated_account_array_size;
}

static unsigned int readAllowanceArray(unsigned char* buffer, unsigned int offset)
{
    unsigned int written_bytes = 0;
    globalAllowanceArray = malloc(sizeof(Allowance) * theContractState.allocated_allowance_array_size);

    for (int i = 0; i < theContractState.allocated_allowance_array_size; i++) {
        memcpy(&globalAllowanceArray[i], buffer+offset, sizeof(Allowance));
        written_bytes += sizeof(Allowance);
        offset += sizeof(Allowance);

        if (i <= theContractState.num_allowance) {
            globalAllowanceArray[i].records = malloc(sizeof(AllowanceRecord) * globalAllowanceArray[i].allocated_array_size);
            memcpy(globalAllowanceArray[i].records, buffer+offset, sizeof(AllowanceRecord) * globalAllowanceArray[i].allocated_array_size);
            written_bytes += sizeof(AllowanceRecord) * globalAllowanceArray[i].allocated_array_size;
            offset += sizeof(AllowanceRecord) * globalAllowanceArray[i].allocated_array_size;
        }
    }

    return written_bytes;
}

static unsigned int writeContractStateToState(unsigned char* buffer, unsigned int offset)
{
    memcpy(buffer+offset, &theContractState, sizeof(ContractState));
    return sizeof(ContractState);
}

static unsigned int writeTokenToState(unsigned char* buffer, unsigned int offset)
{
    memcpy(buffer+offset, &ourToken, sizeof(Token));
    return sizeof(Token);
}

static unsigned int writeAccountArrayToState(unsigned char* buffer, unsigned int offset)
{    
    memcpy(buffer+offset, globalAccountArray, sizeof(Account) * theContractState.allocated_account_array_size);
    return sizeof(Account) * theContractState.allocated_account_array_size;
}

static unsigned int writeAllowanceArrayToState(unsigned char* buffer, unsigned int offset)
{
    unsigned int written_bytes = 0;
    for (int i = 0; i < theContractState.allocated_allowance_array_size; i++) {
        memcpy(buffer+offset+written_bytes, &globalAllowanceArray[i], sizeof(Allowance));
        written_bytes += sizeof(Allowance);
        if (i <= theContractState.num_allowance) {
            memcpy(buffer+offset+written_bytes, globalAllowanceArray[i].records, sizeof(AllowanceRecord) * globalAllowanceArray[i].allocated_array_size);
            written_bytes += sizeof(AllowanceRecord) * globalAllowanceArray[i].allocated_array_size;
        }
    }

    return written_bytes;
}

static unsigned int compute_contract_size()
{
    unsigned int size_sum = 0;

    unsigned int sz_token = sizeof(Token);
    unsigned int sz_contract_state = sizeof(ContractState);
    unsigned int sz_account_array = sizeof(Account) * theContractState.allocated_account_array_size;
    unsigned int sz_allowance_array = sizeof(Allowance) * theContractState.allocated_allowance_array_size;
    unsigned int sz_allowance_records = 0;
    for (int i = 0; i < theContractState.num_allowance; i++) {
        sz_allowance_records += globalAllowanceArray[i].allocated_array_size * sizeof(AllowanceRecord);
    }

    size_sum = sz_token + sz_contract_state + sz_account_array + sz_allowance_array + sz_allowance_records;
    return size_sum;
}

/*
    Following is an example of the way to create / get your data
    Because C does not have mapping, you may have to use 2-D array to store balance
*/


static void initAccountArray()
{
    globalAccountArray = malloc(sizeof(Account) * INIT_ACCOUNT_ARRAY_SIZE);
    globalAccountArray[0] = createAccount(ourToken.contractOwnerAddress);
    globalAccountArray[0].balance = ourToken.totalSupply;

    theContractState.allocated_account_array_size = INIT_ACCOUNT_ARRAY_SIZE;
    theContractState.num_account = 1;
    return;
}

static Account* findAccount(char* address)
{
    for (int i = 0; i < theContractState.num_account; i++) {
        if (!strcmp(globalAccountArray[i].address, address)) {
            return &globalAccountArray[i];
        }
    }

    return NULL;
}

static Account createAccount(char* address)
{
    Account account;

    strcpy(account.address, address);
    account.balance = 0;
    return account;
}

static void appendToAccountArray(Account account)
{
    if (theContractState.num_account < theContractState.allocated_account_array_size) {
        globalAccountArray[theContractState.num_account] = account;
        theContractState.num_account++;
    } else {
        // re-allocate a bigger array
        int new_allocated_account_array_size = theContractState.allocated_account_array_size * 2;
        Account* newAccountArray = malloc(sizeof(Account) * new_allocated_account_array_size);
        
        for (int i = 0; i < theContractState.allocated_account_array_size; i++) {
            newAccountArray[i] = globalAccountArray[i];
        }

        globalAccountArray = newAccountArray;

        globalAccountArray[theContractState.num_account] = account;
        theContractState.num_account++;
        theContractState.allocated_account_array_size = new_allocated_account_array_size;
    }

    return;
}

static void initAllowanceArray()
{
    globalAllowanceArray = malloc(sizeof(Allowance) * INIT_ALLOWANCE_ARRAY_SIZE);
    globalAllowanceArray[0] = createAllowance(&globalAccountArray[0]);

    theContractState.num_allowance = 1;
    theContractState.allocated_allowance_array_size = INIT_ALLOWANCE_ARRAY_SIZE;
    return;
}

static Allowance createAllowance(Account* account)
{
    Allowance allowance;
    
    strcpy(allowance.allownace_owner_address, account->address);
    allowance.record_count = 0;
    allowance.records = malloc(sizeof(AllowanceRecord) * INIT_ALLOWANCE_RECORD_ARRAY_SIZE);
    allowance.allocated_array_size = INIT_ALLOWANCE_RECORD_ARRAY_SIZE;

    return allowance;
}

static Allowance* findAllowance(Account* account)
{
    for (int i = 0; i < theContractState.num_allowance; i++) {
        if (!strcmp(globalAllowanceArray[i].allownace_owner_address, account->address)) {
            return &globalAllowanceArray[i];
        }
    }

    return NULL;
}

static void appendToAllowanceArray(Allowance target_allowance)
{
    if (theContractState.num_allowance < theContractState.allocated_allowance_array_size) {
        globalAllowanceArray[theContractState.num_allowance] = target_allowance;
        theContractState.num_allowance++;
    } else {
        // re-allocate a bigger array
        int new_allocated_allowance_array_size = theContractState.allocated_allowance_array_size * 2;
        Allowance *newAllowanceArray = malloc(sizeof(Allowance) * new_allocated_allowance_array_size);

        for (int i = 0; i < theContractState.allocated_allowance_array_size; i++) {
            newAllowanceArray[i] = globalAllowanceArray[i];
        }

        globalAllowanceArray = newAllowanceArray;

        globalAllowanceArray[theContractState.num_allowance] = target_allowance;
        theContractState.num_allowance++;
        theContractState.allocated_allowance_array_size = new_allocated_allowance_array_size;
    }

    return;
}

static AllowanceRecord* findAllowanceRecord(Allowance *target_allowance, Account* spender_account)
{
    for (int i = 0; i < target_allowance->record_count; i++) {
        if (!strcmp(target_allowance->records[i].spender_address, spender_account->address)) {
            return &target_allowance->records[i];
        }
    }

    return NULL;
}

static AllowanceRecord createAllowanceRecord(Account* account, int amount)
{
    AllowanceRecord record;
    
    record.amount = amount;
    strcpy(record.spender_address, account->address);

    return record;
}

static void appendToAllowanceRecordArray(Allowance *target_allowance, AllowanceRecord record)
{
    if (target_allowance->record_count < target_allowance->allocated_array_size) {
        target_allowance->records[target_allowance->record_count] = record;
        target_allowance->record_count++;
    } else {
        // re-allocate to bigger array
        int new_allocated_array_size = target_allowance->allocated_array_size * 2;
        AllowanceRecord *new_records = malloc(sizeof(AllowanceRecord) * new_allocated_array_size);

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