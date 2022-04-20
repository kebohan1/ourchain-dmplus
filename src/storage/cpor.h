#include <contract/cpor/cpor.h>
#include <serialize.h>
#include <uint256.h>

class CPOR_newParams {
  public:
  /* Parameters */
		unsigned int lambda;		/* The security parameter lambda */
		unsigned int Zp_bits;		/* The size (in bits) of the prime that creates the field Z_p */
		unsigned int prf_key_size;	/* Size (in bytes) of an HMAC-SHA1 */
		unsigned int enc_key_size;	/* Size (in bytes) of the user's AES encryption key */
		unsigned int mac_key_size;	/* Size (in bytes) of the user's MAC key */

		unsigned int block_size;	/* Message block size in bytes */
		unsigned int sector_size;	/* Message sector size in bytes */
		unsigned int num_sectors;	/* Number of sectors per block */
		unsigned int num_challenge;	/* Number of blocks to challenge */
		
		unsigned int num_threads;	/* Number of tagging threads */
		
		char *filename;
		unsigned int filename_len;
		
		unsigned int op;
    CPOR_newParams(){
      lambda = 80; /* The security parameter lambda */

    prf_key_size = 20; /* Size (in bytes) of an HMAC-SHA1 */
    enc_key_size = 32; /* Size (in bytes) of the user's AES encryption key */
    mac_key_size = 20; /* Size (in bytes) of the user's MAC key */

    block_size = 100; /* Message block size in bytes */
    num_threads = 4;
    num_challenge = lambda; /* From the paper, a "conservative choice" for l is lamda, the number of bits to represent our group, Zp */

    filename = NULL;
    filename_len = 0;

    /* The size (in bits) of the prime that creates the field Z_p */
    Zp_bits = lambda;
    /* The message sector size 1 byte smaller than the size of Zp so that it
     * is guaranteed to be an element of the group Zp */
    sector_size = ((Zp_bits / 8) - 1);
    /* Number of sectors per block */
    num_sectors = ((block_size / sector_size) + ((block_size % sector_size) ? 1 : 0));

    };

    ADD_SERIALIZE_METHODS;

    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(lambda);
        READWRITE(Zp_bits);
        READWRITE(prf_key_size);
        READWRITE(enc_key_size);
        READWRITE(mac_key_size);
        READWRITE(block_size);
        READWRITE(sector_size);
        READWRITE(num_sectors);
        READWRITE(num_challenge);
        READWRITE(num_threads);
        READWRITE(op);
    }
};

int local_cpor_tag_file(std::string str, uint256 hash, CPOR_key* pkey);
CPOR_key *allocate_cpor_key(unsigned int enc_key_size, unsigned int mac_key_size);
void destroy_cpor_key(CPOR_key *key, unsigned int enc_key_size, unsigned int mac_key_size);
CPOR_challenge *cpor_create_challenge(CPOR_global *global, unsigned int n);

void destroy_cpor_challenge(CPOR_challenge *challenge);
CPOR_challenge *allocate_cpor_challenge(unsigned int l);
CPOR_t *allocate_cpor_t(unsigned int prf_key_size, unsigned int num_sectors);

CPOR_challenge *cpor_challenge_file(std::string hash, CPOR_key* pkey);
std::vector<unsigned char> SerializeChallenge(CPOR_challenge* challenge);
CPOR_challenge* UnserializeChallenge(std::vector<unsigned char> from);

//Prove files
CPOR_proof *cpor_prove_file(std::string file, std::vector<unsigned char> tagfile, CPOR_challenge *challenge);
std::vector<unsigned char> SerializeProof(CPOR_proof* proof);
CPOR_proof* UnserializeProof(std::vector<unsigned char> from);

//Verify
int cpor_verify_file(std::string hash, CPOR_challenge *challenge, CPOR_proof *proof, CPOR_key* key);

std::vector<unsigned char> SerializeT(CPOR_t* t);
CPOR_t* UnserializeT(std::vector<unsigned char> from);