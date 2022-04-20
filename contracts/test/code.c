#include <ourcontract.h>
#include <string.h>
#include <stdlib.h>

typedef struct {
    char pubkey[50];
    char ip[128];
    int money;
    int nBlockNum;
} IpfsNode;

typedef struct {
  char cCIDHash[40];
  char cAddress[40];
  char time[15];
}ProofBlock;

typedef struct block {
  char CIDHash[40];
  char merkleRoot[129]; // the length of merkle root is 256 bit
  IpfsNode blockSavers[100];
  int nBlockSavers;
  int verified;
  int nProof;
  ProofBlock proof_block_lists[20000];
}Block;

static struct {
    int is_freezed;     // true if the vote already ended
    int nUserCount;
    unsigned int nReplication;
    int nBlockNumber;
    IpfsNode aUsers[100];
    Block aBlocks[100000];
} state;

static int find_user(const char *pubkey)
{
    int i;
    for (i = 0; i < state.nUserCount; i++) {
        if (str_cmp(pubkey, state.aUsers[i].pubkey, 50) == 0) {
            return i;
        }
    }

    return -1;
}

int cmpIPFSNode(IpfsNode node1, IpfsNode node2) {
  if(!strcmp(node1.pubkey,node2.pubkey)) return 1;
  return 0;
}

int findBlock(char* merkle_root) {
  int i = 0;
  for(i = 0; i < state.nBlockNumber; ++i) {
    if(!strcmp(merkle_root, state.aBlocks[i].merkleRoot)) return i;
  }
  return -1;
}

int findBlockSaver(int index, IpfsNode cIpfsnode) {
  int i = 0;
  for(i = 0; i < state.aBlocks[index].nBlockSavers; ++i) {
    if(cmpIPFSNode(state.aBlocks[index].blockSavers[i], cIpfsnode)) return i;
  }
  return 0;
}

int cmpIPFSnodeBlockNum(const void* a, const void* b){
  return ((IpfsNode*)a)->nBlockNum - ((IpfsNode*)b)->nBlockNum;
}

void qsortIPFS(IpfsNode* pIpfsnode,size_t nItems) {
  qsort(pIpfsnode, nItems, sizeof(IpfsNode), cmpIPFSnodeBlockNum);
}


static int sign_up(const char *pubkey)
{
    if (state.is_freezed == 1) return -1;

    /* already signed up */
    if (find_user(pubkey) != -1) return -1;

    /* number of users reaches upper bound */
    if (state.nUserCount == 100) return -1;

    str_printf(state.aUsers[state.nUserCount].pubkey, 50, "%s", pubkey);
    state.aUsers[state.nUserCount].money = 0;
    state.aUsers[state.nUserCount].nBlockNum = 0;

    out_printf("%s,%s\n", state.aUsers[state.nUserCount].pubkey, state.aUsers[state.nUserCount].ip);

    state.nUserCount++;

    return 0;
}

static void state_init()
{
    state.is_freezed = 0;
    state.nUserCount = 0;
    out_clear();
}

static int saveBlock(char* merkle_root, char* CID, IpfsNode* cIpfsnode, char* proofCID, char* time) {
  
  int blockIndex = findBlock(merkle_root);
  Block nowBlock;
  if(blockIndex) {
    // Check if ipfsNode exist in the blocksaver
    int res = findBlockSaver(blockIndex, *cIpfsnode);
    if(res) return -1;

    
  } else {
      // Create the initial block
      strcpy(nowBlock.merkleRoot, merkle_root);
      strcpy(nowBlock.CIDHash,CID);
      nowBlock.nBlockSavers = 0;
  }
  
  /* TODO: Block Upload need to verify by provide the proof of block to check to success. We
   * can implement with the Provable Data Possision (PDP). This should be done before the benckmark
   * 2022-03-13
   */
   // int ret = validateProof(proofCID)
   // if(!ret) return -1;

  if(!blockIndex){ 
    state.aBlocks[state.nBlockNumber] = nowBlock;
  }

  state.aBlocks[state.nBlockNumber].blockSavers[state.aBlocks[state.nBlockNumber].nBlockSavers++] = *cIpfsnode;
  state.nBlockNumber++;
  cIpfsnode->nBlockNum++;
  return 1;
}

static int saveProof(char* merkle_root, char* proofCID, IpfsNode cIpfsnode, char* time) {
  /* TODO: Block Upload need to verify by provide the proof of block to check to success. We
   * can implement with the Provable Data Possision (PDP). This should be done before the benckmark
   * 2022-03-13
   */
   // int ret = validateProof(proofCID)
   // if(!ret) return -1;

  ProofBlock cProofBlock;

  Block cblock = state.aBlocks[findBlock(merkle_root)];

  strcpy(cProofBlock.cAddress, cIpfsnode.pubkey);
  strcpy(cProofBlock.cCIDHash, proofCID);
  strcpy(cProofBlock.time, time);

  cblock.proof_block_lists[cblock.nProof++] = cProofBlock;

  return 1;

}

static int repair(char* merkle_root, IpfsNode misbehabiorNode) {
  
  Block cblock = state.aBlocks[findBlock(merkle_root)];

  IpfsNode pRepairNode;
  //order the least storing node to repair
  // qsortIPFS(state->aSignList,)

}

/*
 * argv[0]: contract id
 * argv[1]: subcommand
 * argv[2...]: args
 */
int contract_main(int argc, char **argv)
{
    if (state_read(&state, sizeof(state)) == -1) {
        err_printf("state_init()\n");
        /* first time call */
        state_init();
        state_write(&state, sizeof(state));
        state_read(&state, sizeof(state));
    }

    if (argc < 2) {
        err_printf("%s: no subcommand\n", argv[0]);
        return 0;
    }

    /* subcommand "sign_up" */
    if (str_cmp(argv[1], "sign_up", 7) == 0) {
        if (argc != 3) {
            err_printf("%s: usage: sign_up user_name user_pubkey\n", argv[0]);
            return 0;
        }

        int ret = sign_up(argv[2]);
        if (ret != 0) {
            err_printf("%s: sign_up failed\n", argv[0]);
            return 0;
        }

        state_write(&state, sizeof(state));
        return 0;
    } else if (strcmp(argv[1], "print") == 0) {
        err_printf("%d\n", state.nUserCount);
    } else if(!str_cmp(argv[1], "save_block", 10)) {
        /*
         * argv[2]: merkle root
         * argv[3]: CID
         * argv[4]: ipfs pubkey
         * argv[5]: proof CID
         * argv[6]: time
         */
        if(argc != 7) return -1;
        int n_ipfs_index = find_user(argv[4]);
        if(n_ipfs_index < 0) return -1;
        IpfsNode cIpfsNode = state.aUsers[n_ipfs_index];
        int ret = saveBlock(argv[2], argv[3], &state.aUsers[n_ipfs_index], argv[5], argv[6]);
        if(ret != 0) return -1;

        state_write(&state, sizeof(state));
        return 0;
    }

    return 0;
}
