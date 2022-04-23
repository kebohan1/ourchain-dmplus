#include <contract/ipfsContract.h>

unsigned int IpfsContract::readContractState(unsigned char* buffer, unsigned int offset)
{
    memcpy(&theContractState, buffer+offset, sizeof(ContractState));
    return sizeof(ContractState);
}

unsigned int IpfsContract::readToken(unsigned char* buffer, unsigned int offset)
{
    memcpy(&ourToken, buffer+offset, sizeof(Token));
    return sizeof(Token);
}

unsigned int IpfsContract::readAccountArray(unsigned char* buffer, unsigned int offset)
{
    globalAccountArray = (Account*)malloc(sizeof(Account) * theContractState.allocated_account_array_size);
    memcpy(globalAccountArray, buffer+offset, sizeof(Account) * theContractState.allocated_account_array_size);
    return sizeof(Account) * theContractState.allocated_account_array_size;
}

unsigned int IpfsContract::readAllowanceArray(unsigned char* buffer, unsigned int offset)
{
    unsigned int written_bytes = 0;
    globalAllowanceArray = (Allowance*)malloc(sizeof(Allowance) * theContractState.allocated_allowance_array_size);

    for (int i = 0; i < theContractState.allocated_allowance_array_size; i++) {
        memcpy(&globalAllowanceArray[i], buffer+offset, sizeof(Allowance));
        written_bytes += sizeof(Allowance);
        offset += sizeof(Allowance);

        if (i <= theContractState.num_allowance) {
            globalAllowanceArray[i].records = (AllowanceRecord*)malloc(sizeof(AllowanceRecord) * globalAllowanceArray[i].allocated_array_size);
            memcpy(globalAllowanceArray[i].records, buffer+offset, sizeof(AllowanceRecord) * globalAllowanceArray[i].allocated_array_size);
            written_bytes += sizeof(AllowanceRecord) * globalAllowanceArray[i].allocated_array_size;
            offset += sizeof(AllowanceRecord) * globalAllowanceArray[i].allocated_array_size;
        }
    }

    return written_bytes;
}

unsigned int IpfsContract::readBlocksArray(unsigned char* buffer, unsigned int offset) {
  unsigned int written_bytes = 0;
  aBlocks = (Block*)malloc(sizeof(Block) * theContractState.allocated_blocks_array_size);

  for(int i = 0; i < theContractState.allocated_blocks_array_size; ++i) {
    memcpy(&aBlocks[i], buffer+offset, sizeof(Block));
    written_bytes += sizeof(Block);
    offset += sizeof(Block);

    if(i <= theContractState.allocated_blocks_array_size) {
      aBlocks[i].blockSavers = new int[aBlocks[i].allocated_blockSavers_size];
      memcpy(aBlocks[i].blockSavers, buffer + offset, sizeof(int) * aBlocks[i].allocated_blockSavers_size);
      written_bytes += sizeof(int) * aBlocks[i].allocated_blockSavers_size;
      offset += sizeof(int) * aBlocks[i].allocated_blockSavers_size;

      aBlocks[i].array_proof_block = (ProofBlock*)malloc(sizeof(ProofBlock) * aBlocks[i].allocated_array_proof_size);
      memcpy(aBlocks[i].array_proof_block, buffer+offset, sizeof(ProofBlock) * aBlocks[i].allocated_array_proof_size);
      written_bytes += sizeof(ProofBlock) * aBlocks[i].allocated_array_proof_size;
      offset += sizeof(ProofBlock) * aBlocks[i].allocated_array_proof_size;
    }
  }

  return written_bytes;
}
unsigned int IpfsContract::readIpfsNodeArray(unsigned char* buffer, unsigned int offset) {
  aIpfsNode = (IPFSNode *) malloc(sizeof(IPFSNode) * theContractState.allocated_ipfsnode_array_size);
  memcpy(aIpfsNode, buffer+offset, sizeof(IPFSNode) * theContractState.allocated_ipfsnode_array_size);
  return sizeof(IPFSNode) * theContractState.allocated_ipfsnode_array_size;
}

/** This function is used to read the state from disk*/
void IpfsContract::init()
{
    unsigned int count;

    LogPrintf("Start read state\n");
    fs::path stateFile = GetDataDir() / "contracts" / address.ToString() / "state";
    FILE* f = fsbridge::fopen(stateFile, "r");
    LogPrintf("Read whole contract size\n");
    fread(&count, sizeof(int), 1, f);
    // state_read(&count, sizeof(int));
    LogPrintf("Count: %d\n",count);
    unsigned char* buff = new unsigned char[count];
    unsigned int offset = 0;
    // state_read(buff, count);
    LogPrintf("read buff\n");
    fread(buff, count, 1, f);

    offset += readContractState(buff, offset);
    offset += readToken(buff, offset);
    offset += readAccountArray(buff, offset);
    offset += readAllowanceArray(buff, offset);
    offset += readBlocksArray(buff, offset);
    offset += readIpfsNodeArray(buff, offset);

    if (offset != count) {
        LogPrintf("Contract Err:offset = %u  count = %u\n", offset, count);
    }
}

std::vector<uint256> IpfsContract::getSavedBlock(std::string pubkey) {
  int ipfs_index = -1;
  std::vector<uint256> vStoredBlock;
  LogPrintf("Inside getSavedBlock\n");
  for(int i = 0; i < theContractState.num_ipfsnode; ++i) {
    LogPrintf("IPFS address: %s, ipfs in contract: %s\n",aIpfsNode[i].address,pubkey.c_str());
    if(!strcmp(aIpfsNode[i].address,pubkey.c_str())) {
      ipfs_index = i;
      LogPrintf("Get ipfs index:%d\n",i);
      break;
    }
  }
  if(ipfs_index == -1) return vStoredBlock;
  LogPrintf("Contract num blocks:%d\n",theContractState.num_blocks);
  for(int i = 0; i < theContractState.num_blocks; ++i) {
    LogPrintf("Block Saver num:%d\n",aBlocks[i].nBlockSavers);
    for(int j = 0; j < aBlocks[i].nBlockSavers; ++j) {
      LogPrintf("Block Saver num index:%d\n",aBlocks[i].blockSavers[j]);
      if(aBlocks[i].blockSavers[j] == ipfs_index) {
        vStoredBlock.push_back(uint256S(aBlocks[i].merkleRoot)); 
        LogPrintf("Find Block:%d\n",i); 
        break;
      }
    }
  }
  return vStoredBlock;
}