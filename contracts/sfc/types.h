#include <string.h>

#define MAX_USER 1000
#define MAX_LENDERS 1000
#define MAX_LOANS 10000

typedef struct address { char x[50]; } address;

typedef struct string { char x[100000]; } string;

// Address Description : address and amount
struct AddressDesc {
    address _address;
    uint64_t _amount;
};

struct AddressApp {
    address _address;
    bool isApproved;
};

enum Status { initial, lent, paid, destroyed }

struct Approbation {
    bool approved;
    short data; // or use char for one byte
    int32_t checksum;
};