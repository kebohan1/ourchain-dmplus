from bitcoinrpc.authproxy import AuthServiceProxy, JSONRPCException

rpc_user = "test"
rpc_password = "123456"

# rpc_user and rpc_password are set in the bitcoin.conf file
# rpc_connection = AuthServiceProxy("http://%s:%s@127.0.0.1:18332"%(rpc_user, rpc_password))
node1 = AuthServiceProxy("http://%s:%s@127.0.0.1:9011"%(rpc_user, rpc_password))
node2 = AuthServiceProxy("http://%s:%s@127.0.0.1:9001"%(rpc_user, rpc_password))

# best_block_hash = rpc_connection.getbestblockhash()
# print(rpc_connection.getblock(best_block_hash))
command = [["getnewaddress"]]
response = node1.batch_(command)
print(response[0])
address = response[0]
miningCommand = [["generatetoaddress","100",address]]
print(miningCommand)
response = node1.batch_(miningCommand)
print(response)


# command = [["deploycontract" , "/home/dmplus/ourchain-dmplus/contracts/ipfscontract/code.c" , "init"]]
# response = rpc_connection.batch_(command)
# print(response["contract address"])