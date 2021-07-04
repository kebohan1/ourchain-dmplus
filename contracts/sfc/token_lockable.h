#include "types.h"
#include "orc20.h"
#include "safe_math.h"

struct TokenLockable {
  public:
    AddressDesc lockedTokens[MAX_USER];
    int lockedTokensLength;

    bool withdrawTokens(ORC20 token, address to, uint64_t amount) {
        if (safeSubtract(token.balanceOf(address(this)), get_value(address(token))) >= amount) {
            if (to != address(0)) {
                if (token.transfer(to, amount)) {
                    return true;
                }
            }
        }
        return false;
    }

  private:
    void lockTokens(address token, uint64_t amount) {
        lockedTokens[lockedTokensLength]._address = token;
        lockedTokens[lockedTokensLength]._amount = safeAdd(lockedToken[token], amount);
        lockedTokensLength++;
    }

    void unlockTokens(address token, uint64_t amount) {
        lockedTokens[lockedTokensLength]._address = token;
        lockedTokens[lockedTokensLength]._amount = safeSubtract(lockedTokens[token], amount);
        lockedTokensLength--;
    }

    // TODO: Replace with red black tree, this is time consuming
    int getValue(address a) {
        int i;
        for (i = 0; i < lockedTokensLength; i++) {
            if (lockedTokens[i]._address == a) {
                return lockedTokens[i]._amount;
            }
        }

        return -1; // Invalid address
    }
};