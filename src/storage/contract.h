#include <stdlib.h>
#include <string> 
#include <core_io.h>
#include <uint256.h>
#include <serialize.h>
#include <contract/processing.h>
#include <util/system.h>
#include <contract/ipfsContract.h>
#include <flatfile.h>
#include <storage/cpor.h>
#include <storage/net_process.h>


class CIPFSNode {

protected:
  
public:
  std::string pubKey;
  std::string ip;
  CIPFSNode(){};
  CIPFSNode(std::string pubKey, std::string ip) : pubKey(pubKey), ip(ip) {}
  ~CIPFSNode(){
    pubKey.clear();
    ip.clear();
  }
  std::string getIP(){
    return ip;
  }

  ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(pubKey);
        READWRITE(ip);
    }

  
};

class StorageContract{
  public:
    std::map<std::string, CIPFSNode> vIPFSNode;
    int nReputation = 0;
    uint256 hash;
    StorageContract(){}
    ~StorageContract(){
      SetNull();
    }

    void SetNull(){
      vIPFSNode.clear();
      nReputation=0;
      hash.SetNull();
    }
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vIPFSNode);
        READWRITE(nReputation);
        READWRITE(hash);
    }
};

class CBlockEach {
  protected:
    
  public :
    std::string CID;
    uint256 hash;
    std::string tfileCID;
    int nHeight;
    CBlockEach(){};
    CBlockEach(std::string CID) : CID(CID){};
    ~CBlockEach(){
      SetNull();
    }
    void Challenge();
    void SetNull(){
      CID.clear();
      hash.SetNull();
      tfileCID.clear();
    }

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(CID);
        READWRITE(tfileCID);
        READWRITE(nHeight);
        READWRITE(hash);
    }

};


class CBlockContractManager {

  protected:
    std::vector<FlatFilePos> vColdPool;
    std::vector<FlatFilePos> vWorkingSet;
    std::map<uint256,CBlockEach> vColdBlock;
    std::map<uint256,StorageContract> vStorageContract;
    int n_max_cold_pool = 0;
    int init = 0;
    int n_last_challenge_height = 0;
    
    

  public:
    CPOR_key* pkey = NULL;
    CPOR_newParams cParams;
    CBlockContractManager(){
      // InitParams();
    //  InitKey();
    //   LogPrintf("init cmp\n"); 
    };

    ~CBlockContractManager(){
      SetNull();
    }
    void appendColdPool(FlatFilePos pair);
    bool deployContract(std::vector<CStorageMessage> &);
    void receiveContract(IpfsContract&);
    CBlock* retrieveBlock(uint256);
    
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vColdPool);
        READWRITE(vColdBlock);
        READWRITE(vWorkingSet);
        READWRITE(vStorageContract);
        READWRITE(n_max_cold_pool);
        READWRITE(n_last_challenge_height);
        READWRITE(init);
        READWRITE(cParams);

    }

    void operator=(CBlockContractManager c) {
      vColdPool = c.vColdPool;
      vColdBlock = c.vColdBlock;
      vWorkingSet = c.vWorkingSet;
      vStorageContract = c.vStorageContract;
      pkey = c.pkey;
      cParams = c.cParams;
    }
    void setInit(){
      init = 1;
    }

    void SetNull(){
      destroy_cpor_key(pkey,cParams.enc_key_size,cParams.mac_key_size);
      vColdPool.clear();
      vColdBlock.clear();
      vWorkingSet.clear();
      vStorageContract.clear();
    }

    bool isInit() {
      return init;
    }
    int InitKey();
    void InitParams();
    int ReadKey();

    void workingSet(uint256 hash,FlatFilePos);
    std::vector<CStorageMessage> pushColdPool();
    void automaticColdPool();
    void hotColdClassifier(CBlock* block);
    bool lookupColdPool(FlatFilePos pos);
    bool lookupWorkingSet(FlatFilePos pos);
    void GetBackFromIPFS(CBlock& block, FlatFilePos pos);
    void challengeBlock(int nHeight);
};



// void mergeIPFSList(std::vector<CIPFSNode> &vIPFSList, int left, int right, int mid) {
//   std::vector<CIPFSNode> vIPFSLeft(vIPFSList.begin()+left,vIPFSList.begin()+mid);
//   std::vector<CIPFSNode> vIPFSRight(vIPFSList.begin()+mid+1,vIPFSList.begin()+right);

//   int nIdxLeft = 0, nIdxRight = 0, nIdxIPFSList;
//   while(nIdxLeft<vIPFSLeft.size()&&nIdxRight<vIPFSRight.size()){
//     if(vIPFSLeft[nIdxLeft].getRepuatation()<vIPFSRight[nIdxRight].getRepuatation()) {
//       vIPFSList[nIdxIPFSList++] = vIPFSLeft[nIdxLeft++];
//     } else {
//       vIPFSList[nIdxIPFSList++] = vIPFSLeft[nIdxRight++];
//     }
//   }

//   while(nIdxLeft<vIPFSLeft.size()) {
//     vIPFSList[nIdxIPFSList++] = vIPFSLeft[nIdxLeft++];
//   }

//   while(nIdxRight<vIPFSRight.size()) {
//     vIPFSList[nIdxIPFSList++] = vIPFSLeft[nIdxRight++];
//   }

// }

// void IPFSMergeSort(std::vector<CIPFSNode> &vIPFSNode, int left, int right) {
//   if(left >= right) return;
//   int mid = (left + right) / 2;
//   IPFSMergeSort(vIPFSNode, left, right);
//   IPFSMergeSort(vIPFSNode, left + 1, right);
//   mergeIPFSList(vIPFSNode, left, mid, right);
// }

// uint256 deploySysContract(CBlock& pblock);