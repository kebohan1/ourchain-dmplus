from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

rpc_user = "test"
rpc_password = "123456"

# rpc_user and rpc_password are set in the bitcoin.conf file
rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:18332"%(rpc_user, rpc_password))
# best_block_hash = rpc_connection.getbestblockhash()
# print(rpc_connection.getblock(best_block_hash))

command = [["callcontract" , "8ebce0920f628438777f8d552705b048abf0e3847c9067211114549fbf3162cd" , "printAllBlocks"]]
response = rpc_connection.batch_(command)
print(response)