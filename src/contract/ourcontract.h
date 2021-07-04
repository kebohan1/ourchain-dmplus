#ifndef BITCOIN_CONTRACT_OURCONTRACT_H
#define BITCOIN_CONTRACT_OURCONTRACT_H

#define BYTE_READ_STATE 0
#define BYTE_SEND_TO_ADDRESS -1
#define BYTE_SEND_TO_CONTRACT -2
#define BYTE_CALL_CONTRACT -3

#include <stdint.h>
#include <stdbool.h>

/** Amount in satoshis (Can be negative) */
typedef int64_t CAmount;

#define COIN ((CAmount)100000000)
#define CENT ((CAmount)1000000)

/** No amount larger than this (in satoshi) is valid.
 *
 * Note that this constant is *not* the total money supply, which in Bitcoin
 * currently happens to be less than 21,000,000 BTC for various reasons, but
 * rather a sanity check. As this sanity check is used by consensus-critical
 * validation code, the exact value of the MAX_MONEY constant is consensus
 * critical; in unusual circumstances like a(nother) overflow bug that allowed
 * for the creation of coins out of thin air modification could lead to a fork.
 * */
static const CAmount MAX_MONEY = 21000000 * COIN;
inline bool MoneyRange(const CAmount nValue) { return (nValue >= 0 && nValue <= MAX_MONEY); }

static const int64_t UPPER_BOUND = 1000000000000000000LL - 1LL;

/* non-reentrant entry point of runtime */
int start_runtime(int argc, char **argv);

/* contract call can be nested */
int call_contract(const char *contract, int argc, char **argv);

/* print to runtime error log */
int err_printf(const char *format, ...);

/* wrapper around snprintf */
int str_printf(char *str, unsigned size, const char *format, ...);

/* wrapper around strncmp */
int str_cmp(const char *s1, const char *s2, int n);

/* print to contract output */
int out_printf(const char *format, ...);

/* clear contract output */
int out_clear(void);

/* read the state file of the calling contract */
int state_read(void *buf, int count);

/* write the state file of the calling contract */
int state_write(const void *buf, int count);

/* send some money to the target address */
int send_money(const char *addr, CAmount amount);

/* send some money to the target contract */
int send_money_to_contract(const char *addr, CAmount amount);

CAmount amount_from_string(const char *val);

#endif // BITCOIN_CONTRACT_OURCONTRACT_H