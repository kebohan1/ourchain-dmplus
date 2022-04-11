#include <stdlib.h>
#include <string> 
#include <core_io.h>
#include <uint256.h>

class CIPFSNode {

protected:
  uint256 pubKey;
  int nReputation = 0;
public:
  CIPFSNode(uint256 pubKey) : pubKey(pubKey) {}
  CIPFSNode(uint256 pubKey, int nReputation) : pubKey(pubKey), nReputation(nReputation) {}
  void setReputation(int newRepuation) {
    nReputation = newRepuation;
  }

  int getRepuatation(){
    return nReputation;
  }
  
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

uint256 deploySysContract(std::string blkname);