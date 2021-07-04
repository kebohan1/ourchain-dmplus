#!/bin/bash
src/bitcoin-cli -regtest generatetoaddress 101 $1
src/bitcoin-cli -regtest deploycontract contracts/hello/code.c 123
