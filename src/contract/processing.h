#ifndef BITCOIN_CONTRACT_PROCESSING_H
#define BITCOIN_CONTRACT_PROCESSING_H

#include "contract/contract.h"
#include "primitives/transaction.h"
#include "amount.h"

#include <vector>

typedef unsigned char uchar;

bool ProcessContract(const Contract &contract, std::vector<CTxOut> &vTxOut, std::vector<uchar> &state, CAmount balance,
					 std::vector<Contract> &nextContract);
					 
#endif // BITCOIN_CONTRACT_PROCESSING_H
