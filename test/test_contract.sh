#!/bin/bash
src/bitcoin-cli --regtest callcontract $1 user_sign_up $2
src/bitcoin-cli --regtest generatetoaddress 1 $2
src/bitcoin-cli --regtest callcontract $1 save_block 0xaeca09748f19c18e6f4954d674810ae39b888a96a530ffb16206b300a8c10cd3 QmdUxuxB6ks5dU6da8Lr12u84QBUaFRWHQqugZgM5hGp1m $2 QmdUxuxB6ks5dU6da8Lr12u84QBUaFRWHQqugZgM5hGp1m 1649817857
# src/bitcoin-cli --regtest deploycontract contracts/hello/code.c 123
src/bitcoin-cli --regtest generatetoaddress 1 $2