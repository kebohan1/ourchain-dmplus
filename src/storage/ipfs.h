#include <stdlib.h>
#include <string> 
#include <core_io.h>
#include <uint256.h>
#include <serialize.h>
// #include <contract/cpor/cpor.h>
// #include <contract/contract.h>
#include <util/system.h>
// #include <flatfile.h>
#include <storage/net_process.h>
// #include <storage/contract.h>
// #include <net.h>

class IpfsStoredBlock {
  public:
  std::string CID;
  std::string TagCID;
  uint256 hash;

  ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(CID);
        READWRITE(TagCID);
        READWRITE(hash);
    }
};

class IpfsStorageManager {

  

  public:

  std::vector<uint256> vStoredContract;
  std::vector<CStorageMessage> vReadySolvingMsg;
  std::map<uint256 ,IpfsStoredBlock> vStoredBlock;
  uint256 contractHash;
  std::string RegisterKey;

    IpfsStorageManager(){};
    void receiveMessage(std::vector<CStorageMessage> msgs);
    void receiveChallengeMessage(std::vector<ChallengeMessage> msgs);
    void init();
    void FlushDisk();
    void DynamicStoreBlocks(int);
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vStoredContract);
        READWRITE(vReadySolvingMsg);
        READWRITE(vStoredBlock);
        READWRITE(contractHash);
        READWRITE(RegisterKey);
    }
};