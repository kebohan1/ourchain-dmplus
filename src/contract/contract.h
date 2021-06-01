#ifndef BITCOIN_CONTRACT_CONTRACT_H
#define BITCOIN_CONTRACT_CONTRACT_H

#include "serialize.h"
#include "uint256.h"

#include <stdint.h>
#include <string>
#include <vector>

enum contract_action
{
    ACTION_NONE     = 0,
    ACTION_NEW      = 1,
    ACTION_CALL     = 2,
};

class Contract
{
public:
    uint8_t action;                 //!< ACTION_XXX
    std::string code;               //!< contract code if ACTION_NEW
    uint256 address;            //!< contract address
    std::vector<std::string> args;  //!< passed arguments

    Contract()
    {
        SetNull();
    }

    Contract(const Contract &contract) : action(contract.action), code(contract.code), address(contract.address), args(contract.args) {}

    ~Contract()
    {
        SetNull();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(this->action);
        READWRITE(code);
        READWRITE(address);
        READWRITE(args);
    }

    void SetNull()
    {
        action = 0;
        code.clear();
        address.SetNull();
        args.clear();
    }

    bool IsNull() const
    {
        return (action == 0);
    }
};

#endif // BITCOIN_CONTRACT_CONTRACT_H
