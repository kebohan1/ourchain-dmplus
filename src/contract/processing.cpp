#include "contract/processing.h"
// #include "util.h"
#include <logging.h>
#include "primitives/transaction.h"
#include "script/standard.h"
#include "base58.h"
#include "uint256.h"
#include "amount.h"

#include <string>
#include <fstream>
#include <vector>

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <util/system.h>
#include <key_io.h>

#define BYTE_READ_STATE 0
#define BYTE_SEND_TO_ADDRESS -1
#define BYTE_SEND_TO_CONTRACT -2
#define BYTE_CALL_CONTRACT -3

static fs::path contracts_dir;

const static fs::path &GetContractsDir()
{
    if(!contracts_dir.empty()) return contracts_dir;

    contracts_dir = GetDataDir() / "contracts";
    fs::create_directories(contracts_dir);

    return contracts_dir;
}

static int call_mkdll(const uint256& contract)
{
    int pid, status;

    pid = fork();
    if(pid == 0) {
        int fd = open((GetContractsDir().string() + "/err").c_str(),
                      O_WRONLY | O_APPEND | O_CREAT,
                      0664);
        dup2(fd, STDERR_FILENO);
        close(fd);

        execlp("ourcontract-mkdll",
               "ourcontract-mkdll",
               GetContractsDir().string().c_str(),
               contract.GetHex().c_str(),
               NULL);
        exit(EXIT_FAILURE);
    }

    waitpid(pid, &status, 0);
    if (WIFEXITED(status) == false) return -1;
    if (WEXITSTATUS(status) != 0) return -1;
    return 0;
}

static int call_rt(const uint256& contract, const std::vector<std::string> &args, std::vector<CTxOut> &vTxOut,
                   std::vector<uchar> &state, std::vector<Contract> &nextContract)
{
    int pid, status;
    int fd_state_read[2], fd_state_write[2];
    if (pipe(fd_state_read) == -1) return -1;
    if (pipe(fd_state_write) == -1) return -1;

    pid = fork();
    if(pid == 0) {
        int fd_error = open((GetContractsDir().string() + "/err").c_str(),
                      O_WRONLY | O_APPEND | O_CREAT,
                      0664);
        dup2(fd_error, STDERR_FILENO);
        close(fd_error);

        // state & TX
        dup2(fd_state_read[1], STDOUT_FILENO);
        dup2(fd_state_write[0], STDIN_FILENO);
        close(fd_state_read[0]);
        close(fd_state_read[1]);
        close(fd_state_write[0]);
        close(fd_state_write[1]);
        const char **argv = (const char**)malloc((args.size() + 4) * sizeof(char*));
        argv[0] = "ourcontract-rt";
        argv[1] = GetContractsDir().string().c_str();
        std::string hex_ctid(contract.GetHex());
        argv[2] = hex_ctid.c_str();
        for (unsigned i = 0; i < args.size(); i++) argv[i + 3] = args[i].c_str();
        argv[args.size() + 3] = NULL;
        execvp("ourcontract-rt", (char* const*)argv);
        exit(EXIT_FAILURE);
    }
    // read or write state or send money
    close(fd_state_read[1]);
    close(fd_state_write[0]);

    FILE *pipe_state_read = fdopen(fd_state_read[0], "rb");
    FILE *pipe_state_write = fdopen(fd_state_write[1], "wb");

    int flag;
    while (fread((void *) &flag, sizeof(int), 1, pipe_state_read) != 0) {
        if (flag == BYTE_READ_STATE) {                // read state
            fwrite((void *) &state[0], state.size(), 1, pipe_state_write);
        } else if (flag > 0) {          // write state
            state.resize(flag);
            int ret = fread((void *) &state[0], state.size(), 1, pipe_state_read);
            assert(ret >= 0);
        } else if (flag == BYTE_SEND_TO_ADDRESS) {        // send to address
            std::string addr_to( 40, '\0' );
            CAmount amount;
            int ret = fread(&addr_to[0], sizeof(char), (size_t)40, pipe_state_read);
            assert(ret >= 0);
            ret = fread((void *) &amount, sizeof(long long), 1, pipe_state_read);
            assert(ret >= 0);
            CTxDestination address =DecodeDestination(addr_to);
            vTxOut.push_back(CTxOut(amount, GetScriptForDestination(address)));
        } else if (flag == BYTE_SEND_TO_CONTRACT) {        // send to contract
            char addr_to[64];
            CAmount amount;
            int ret = fread((void *) addr_to, sizeof(char), 64, pipe_state_read);
            assert(ret >= 0);
            ret = fread((void *) &amount, sizeof(long long), 1, pipe_state_read);
            assert(ret >= 0);
            uint256 address = uint256S(addr_to);
            vTxOut.push_back(CTxOut(amount, GetScriptForDestination(address)));
        } else if (flag == BYTE_CALL_CONTRACT) {
            Contract contract;
            contract.action = ACTION_CALL;
            char contractName[65] = {0};
            int ret = fread((void *) contractName, sizeof(char), 64, pipe_state_read);
            assert(ret >= 0);
            contract.address = uint256S(contractName);
            int argc;
            ret = fread((void *) &argc, sizeof(int), 1, pipe_state_read);
            assert(ret >= 0);
            for (int i = 0; i < argc; i++) {
                int argLen;
                ret = fread((void *) &argLen, sizeof(int), 1, pipe_state_read);
                assert(ret >= 0);
                char *argName = new char[argLen + 1]();
                ret = fread((void *) argName, sizeof(char), argLen, pipe_state_read);
                assert(ret >= 0);
                contract.args.push_back(std::string(argName));
            }
            nextContract.push_back(contract);
        } else {
            puts("Error: pipe");
        }
    }
    fclose(pipe_state_read);
    fclose(pipe_state_write);

    waitpid(pid, &status, 0);
    if (WIFEXITED(status) == false) return -1;
    if (WEXITSTATUS(status) != 0) return -1;
    return 0;
}

bool ProcessContract(const Contract &contract, std::vector<CTxOut> &vTxOut, std::vector<uchar> &state, CAmount balance,
                     std::vector<Contract> &nextContract)
{
    if (contract.action == contract_action::ACTION_NEW) {
        fs::path new_dir = GetContractsDir() / contract.address.GetHex();
        fs::create_directories(new_dir);
        std::ofstream contract_code(new_dir.string() + "/code.c");
        contract_code.write(contract.code.c_str(), contract.code.size());
        contract_code.close();

        if (call_mkdll(contract.address) < 0) {
            /* TODO: clean up files */
            return false;
        }

        if (call_rt(contract.address, contract.args, vTxOut, state, nextContract) < 0) {
            /* TODO: perform state recovery */
            return false;
        }
    } else if (contract.action == contract_action::ACTION_CALL) {
        if (call_rt(contract.address, contract.args, vTxOut, state, nextContract) < 0) {
            /* TODO: perform state recovery */
            return false;
        }
    }
    CAmount amount = 0;
    for (CTxOut &out :vTxOut) {
        amount = amount + out.nValue;
    }
    if(amount > balance) {
        /* TODO: perform state recovery */
        return false;
    }

    return true;
}
