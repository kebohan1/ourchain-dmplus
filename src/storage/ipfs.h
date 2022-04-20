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
// #include <net.h>



class IpfsStorageManager {

  

  public:

  std::vector<uint256> vStoredContract;
  std::vector<CStorageMessage> vReadySolvingMsg;
  uint256 contractHash;
  std::string RegisterKey;

    IpfsStorageManager(){};
    void receiveMessage(std::vector<CStorageMessage> msgs);
    void init();
    void FlushDisk();
    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(vStoredContract);
        READWRITE(vReadySolvingMsg);
        READWRITE(contractHash);
        READWRITE(RegisterKey);
    }
};