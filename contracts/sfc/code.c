#include <ourcontract.c>
#include "token_lockable.h"
#include "types.h"
#include "oracle.h"

struct Loan {
    Status status;
    Oracle oracle;
    address borrower;
    address lender;
    // address cosigner; // insurance company

    uint64_t amount;
    uint64_t interest;
    uint64_t punitoryInterest;
    uint64_t interestTimestamp;
    uint64_t paid;
    uint64_t interestRate;
    uint64_t interestRatePunitory;
    uint64_t dueTime;
    uint64_t duesIn;

    uint64_t lenderBalance;
    bool approvedByBuyer;
    address approvedTransfer;
    uint64_t expirationRequest;

    string metadata;
    AddressApp approbations[MAX_LENDERS]; // TODO: this is memory inefficient
};

static struct {
    int activeLoans;
    int lendersLength;
    AddressDesc lendersBalance[MAX_LENDERS];
    Loan loans[MAX_LOANS];
    user users[MAX_USER];
} state;

// TODO: Replace with red-black tree, this is time consuming
static uint64_t balance_of(address _owner) {
    int i;
    for (i = 0; i < state.lendersLength; i++) {
        if (state.lendersBalance[i]._address == _owner) {
            return state.lendersBalance[i]._amount;
        }
    }
    return -1; // invalid address
}

static string tokenMetadata(uint64_t index) {
    return loans[index].metadata;
}

static uint32_t tokenMetadataHash(uint64_t index) {
    sha256(loans[index].metadata);
}

uint64_t create_loan(Oracle _oracleContract, address _borrower, uint64_t _amount, uint64_t _interestRate, uint64_t _interestRatePunitory, 
                 uint64_t _duesIn, uint64_t _expirationRequest, string _metadata) {
    Loan loan = Loan(Status.initial, _oracleContract, _borrower, address(0), _amount, _interstRate, _interestRatePunitory, 0, _duesIn,
                     0, address(0), _expirationRequest, _metadata)
    state.loans[activeLoans++] = loan;

    if (msg.sender == _borrower) {
        approveLoan(index);
    }

    return index;
}

/*
 * Used to know if a loan is ready to lend
 * Return true if the loan has been approved by the borrower
 */ 

bool isApproved(uint64_t index) {
    Loan loan = state.loans[index];
    return loan.approbations[loan.borrower];
}

/*
 * Called by the members of the loan to show that they agree with the terms of loan;
 * the borrower must call this method before any lender could call the method "lend".
 */
bool approveLoan(uint64_t index) {
    Loan loan = state.loans[index];
    if (loan.status == Status.initial) {
        loan.approbations[msg.sender] = true;
    }

    return false;
}

/*
 * Performs the lend to the requested amount, and transforms the msg.sender in the new lender
 * The loan must be previously approved by the borrower
 * The lender candidate must call the approve function on the OUR Token
 * Return true if the lend was done successfully
 */ 
bool lend(uint64_t index, short oracleData) {
    Loan &loan = state.loans[index];
    if (loan.status == Status.initial && isApproved(index) && block.timestamp <= loan.expirationRequest) {
        loan.lender = msg.sender;
        loan.dueTime = safeAdd(block.timestamp, loan.duesIn);
        loan.interestTimestamp = block.timestamp;

    }
}

/*
 * Transfer a loan to a borrower,
 * Required for ORC20 compliance
 */

bool transfer(address to, uint64_t index) {
    Loan &loan = state.loans[index];
    if (msg.sender == loan.lender || msg.sender == loan.approvedTransfer) {
        assert(to != address(0));

        // ORC20, transfer a loan to another address
        state.lendersBalance[loan.lender] -= 1;
        state.lendersBalance[to] += 1;
        Transfer(loan.lender, to, index);

        loan.lender = to;
        loan.approvedTransfer = address(0);
        return true;
    }
    return false;
}

/*
 * Transfer from lender to borrower
 * Required for ORC20 compliance
 */
bool transferFrom(address from, address to, uint64_t index) {
    if (state.loans[index].lender == from) {
        return transfer(to, index);
    }
    return false;
}

bool approve(address to, uint64_t index) {

}

void calculateInterest(uint64_t timeDelta, uint64_t interestRate, uint64_t &interest, uint64_t &realDelta) {    
    interest = 0;
    realDelta = timeDelta;
}

/* Do I need this function? */
void internalAddInterest(Loan loan, uint64_t timestamp) {
    if (timestamp > loan.interestTimestamp) {
        uint64_t newInterest = loan.interest;
        uint64_t newPunitoryInterest = loan.punitoryInterest;

        uint64_t newTimestamp;
        uint64_t realDelta;
        uint64_t calculatedInterest;

        uint64_t deltaTime;

        uint64_t endNonPunitory = min(timestamp, loan.dueTime);
        /* Non-punitory interest */
        if (endNonPunitory > loan.interestTimeStamp) {
            deltaTime = endNonPunitory - loan.interestTimeStamp;

            assert(loan.paid == loan.amount);

            calculateInterest(deltaTime, loan.interestRate, realDelta, calculatedInterest);
            newInterest = safeAdd(calculatedInterest, newInterest);
            newTimeStamp = loan.interestTimestamp + realDelta;
        }
        /* Punitory interest */
        if (timeStamp > loan.dueTime) {
            uint64_t startPunitory = max(loan.dueTime, loan.interestTimestamp);
            deltaTime = timestamp - startPunitory;

            uint64_t debt = safeAdd(loan.amount, newInterest);
            calculateInterest(deltaTime, loan.interestRate, realDelta, calculatedInterest);
            newPunitoryInterest = safeAdd(newPunitoryInterest, calculatedInterest);
            newTimestamp = startPunitory + realDelta;
        }

        if (newInterest != loan.interest || newPunitoryInterest != loan.punitoryInterest) {
            loan.interestTimestamp = newTimestamp;
            loan.interest = newInterest;
            loan.punitoryInterest = newPunitoryInterest;
        }
    }
}

/*
 * Updates the loan accumulated interests up to the current Unix time
 * TODO: block.timestamp???
 */
bool addInterest(uint64_t index) {
    Loan loan = state.loans[index];
    if (loan.status == Status.lent) {
        internalAddInterest(loan, block.timestamp);
        return true;
    }
    return false;
}

bool pay(uint64_t index, uint64_t _amount, address _from, short oracleData) {

}

uint64_t convertRate(Oracle oracle, short data, uint64_t amount) {

}

bool withdrawal(uint64_t index, address to, uint64_t amount) {

}

static void state_init()
{
    state.activeLoans = 0;
    state.lendersLength = 0;
    out_clear();
}

int contract_main(int argc, char **argv)
{
    return 0;
}