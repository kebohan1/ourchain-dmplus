#include <storage/cpor.h>
// #include <uint256.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <storage/ipfs_interface.h>

CPOR_newParams cNewParams;
static CPOR_t *read_cpor_t(FILE *tfile, CPOR_key *pkey){
	
	CPOR_t *t = NULL;
	unsigned char *tbytes = NULL;
	unsigned char *t0 = NULL;
	unsigned char *t0_mac = NULL;
	unsigned char *plaintext = NULL;
	unsigned char *ptp = NULL;
	unsigned char *alpha = NULL;
	size_t tbytes_size = 0;
	size_t t0_size = 0;
	size_t t0_mac_size = 0;
	size_t plaintext_size = 0;
	size_t alpha_size = 0;
	int i = 0;
	
	if(!tfile) return 0;
	
	if( ((t = allocate_cpor_t()) == NULL)) goto cleanup;
	// std::cout << "allocate t cmp" <<std::endl;
	/* Read t out of the file */
	fread(&tbytes_size, sizeof(size_t), 1, tfile);
	if(ferror(tfile)) goto cleanup;
	if( ((tbytes = (unsigned char*)malloc(tbytes_size)) == NULL)) goto cleanup;
	fread(tbytes, tbytes_size, 1, tfile);
	if(ferror(tfile)) goto cleanup;	
	// std::cout << "Read t cmp" <<std::endl;



	/* Parse t */
	memcpy(&t0_size, tbytes, sizeof(size_t));
	if( ((t0 = (unsigned char*)malloc(t0_size)) == NULL)) goto cleanup;
	memcpy(t0, tbytes + sizeof(size_t), t0_size);
	memcpy(&t0_mac_size, tbytes + sizeof(size_t) + t0_size, sizeof(size_t));
	if( ((t0_mac = (unsigned char*)malloc(t0_mac_size)) == NULL)) goto cleanup;
	memcpy(t0_mac, tbytes + sizeof(size_t) + t0_size + sizeof(size_t), t0_mac_size);
	// std::cout << "Parse t cmp" <<std::endl;
	
	/* Verify and decrypt t0 */
	if( ((plaintext =(unsigned char*) malloc(t0_size)) == NULL)) goto cleanup;
	memset(plaintext, 0, t0_size);
	if(!decrypt_and_verify_secrets(pkey, t0 + sizeof(unsigned int), t0_size - sizeof(unsigned int), plaintext, &plaintext_size, t0_mac, t0_mac_size)) goto cleanup;
	// std::cout << "Verify t cmp" <<std::endl;
	

	/* Populate the CPOR_t struct */
	memcpy(&(t->n), t0, sizeof(unsigned int));
	ptp = plaintext;
	memcpy(t->k_prf, plaintext, cNewParams.prf_key_size);
	ptp += cNewParams.prf_key_size;
	for(i=0; i < cNewParams.num_sectors; i++){
		memcpy(&alpha_size, ptp, sizeof(size_t));
		ptp += sizeof(size_t);
		if( ((alpha = (unsigned char*)malloc(alpha_size)) == NULL)) goto cleanup;
		memset(alpha, 0, alpha_size);
		memcpy(alpha, ptp, alpha_size);
		ptp += alpha_size;
		if(!BN_bin2bn(alpha, alpha_size, t->alpha[i])) goto cleanup;
		sfree(alpha, alpha_size);
	}	
	// std::cout << "Populate t cmp" <<std::endl;


	if(plaintext) sfree(plaintext, plaintext_size);
	if(tbytes) sfree(tbytes, tbytes_size);
	if(t0) sfree(t0, t0_size);
	if(t0_mac) sfree(t0_mac, t0_mac_size);
	
	return t;
	
cleanup:
	if(plaintext) sfree(plaintext, plaintext_size);
	if(alpha) sfree(alpha, alpha_size);
	if(tbytes) sfree(tbytes, tbytes_size);
	if(t0) sfree(t0, t0_size);
	if(t0_mac) sfree(t0_mac, t0_mac_size);
	if(t) destroy_cpor_t(t);

	return NULL;
}

int encrypt_and_authentucate_secrets(CPOR_key *key, unsigned char *input, size_t input_len, unsigned char *ciphertext, size_t *ciphertext_len, unsigned char *authenticator, size_t *authenticator_len){
	
	EVP_CIPHER_CTX* ctx;
	EVP_CIPHER *cipher = NULL;
	int len;
	
	if(!key || !key->k_enc || !key->k_mac || !input || !input_len || !ciphertext || !ciphertext_len || !authenticator || !authenticator_len) return 0;
	
	OpenSSL_add_all_algorithms();
	
	ctx = EVP_CIPHER_CTX_new();
	switch(key->k_enc_size){
		case 16:
			cipher = (EVP_CIPHER *)EVP_aes_128_cbc();
			break;
		case 24:
			cipher = (EVP_CIPHER *)EVP_aes_192_cbc();
			break;
		case 32:
			cipher = (EVP_CIPHER *)EVP_aes_256_cbc();
			break;
		default:
			return 0;
	}
	//TODO: Fix the NULL IV
	if(!EVP_EncryptInit(ctx, cipher, key->k_enc, NULL)) goto cleanup;

	*ciphertext_len = 0;
	
	if(!EVP_EncryptUpdate(ctx, ciphertext, (int *)ciphertext_len, input, input_len)) goto cleanup;
	EVP_EncryptFinal(ctx, ciphertext + *ciphertext_len, &len);
		
	*ciphertext_len += len;
	
	*authenticator_len = 0;
	/* Do the HMAC-SHA1 */
	if(!HMAC(EVP_sha1(), key->k_mac, key->k_mac_size, ciphertext, *ciphertext_len,
		authenticator, (unsigned int *)authenticator_len)) goto cleanup;
	
	EVP_CIPHER_CTX_free(ctx);
	
	return 1;
	
cleanup:
	*ciphertext_len = 0;
	*authenticator_len = 0;
	
	return 0;
	
}

void destroy_cpor_key(CPOR_key *key, unsigned int enc_key_size, unsigned int mac_key_size) {
  if(!key) return;
	if(key->k_enc) sfree(key->k_enc, enc_key_size);
	key->k_enc_size = 0;
	if(key->k_mac) sfree(key->k_mac, mac_key_size);
	key->k_mac_size = 0;
	if(key->global) destroy_cpor_global(key->global);
	sfree(key, sizeof(CPOR_key));

	return;
}

void destroy_cpor_key(CPOR_key *key){

	if(!key) return;
	if(key->k_enc) sfree(key->k_enc, cNewParams.enc_key_size);
	key->k_enc_size = 0;
	if(key->k_mac) sfree(key->k_mac, cNewParams.mac_key_size);
	key->k_mac_size = 0;
	if(key->global) destroy_cpor_global(key->global);
	sfree(key, sizeof(CPOR_key));

	return;
}

void destroy_cpor_t(CPOR_t *t){

	int i;

	if(!t) return;
	if(t->k_prf) sfree(t->k_prf, cNewParams.prf_key_size);
	if(t->alpha){
		for(i = 0; i < cNewParams.num_sectors; i++)
			if(t->alpha[i]) BN_clear_free(t->alpha[i]);
		 sfree(t->alpha, sizeof(BIGNUM *) * cNewParams.num_sectors);
	}
	t->n = 0;
	sfree(t, sizeof(CPOR_t));
	
	return;
}

void destroy_cpor_global(CPOR_global *global){

	if(!global) return;
	if(global->Zp) BN_clear_free(global->Zp);
	sfree(global, sizeof(CPOR_global));
	
	return;
}

void destroy_cpor_proof(CPOR_proof *proof){

	int i = 0;

	if(!proof) return;
	if(proof->sigma) BN_clear_free(proof->sigma);
	if(proof->mu){
		for(i = 0; i < cNewParams.num_sectors; i++){
			if(proof->mu[i]) BN_clear_free(proof->mu[i]);
		}
		sfree(proof->mu, sizeof(BIGNUM *) * cNewParams.num_sectors);
	}
	sfree(proof, sizeof(CPOR_proof));

	return;	
}

BIGNUM *generate_prf_i(unsigned char *key, unsigned int index){
	
	unsigned char *prf_result = NULL;
	size_t prf_result_size = 0;
	BIGNUM *prf_result_bn = NULL;
	
	if(!key) return NULL;
	
	/* Allocate memory */
	if( ((prf_result = (unsigned char*) malloc(EVP_MAX_MD_SIZE)) == NULL)) goto cleanup;
	memset(prf_result, 0, EVP_MAX_MD_SIZE);
	if( ((prf_result_bn = BN_new()) == NULL)) goto cleanup;
	
	/* Do the HMAC-SHA1 */
	if(!HMAC(EVP_sha1(), key, cNewParams.prf_key_size, (unsigned char *)&index, sizeof(unsigned int),
		prf_result, (unsigned int *)&prf_result_size)) goto cleanup;
		
	/* Convert PRF result into a BIGNUM */
	if(!BN_bin2bn(prf_result, prf_result_size, prf_result_bn)) goto cleanup;
	
	/* Free some memory */
	if(prf_result) sfree(prf_result, EVP_MAX_MD_SIZE);	
	
	return prf_result_bn;
	
cleanup:
	if(prf_result) sfree(prf_result, EVP_MAX_MD_SIZE);
	if(prf_result_bn) BN_clear_free(prf_result_bn);
	return NULL;
	
}

CPOR_t *allocate_cpor_t(){

	CPOR_t *t = NULL;
	int i = 0;
	
  
	if( ((t = (CPOR_t*) malloc(sizeof(CPOR_t))) == NULL)) return NULL;
	memset(t, 0, sizeof(CPOR_t));
	t->n = 0;
  // t->k_prf = new unsigned char[prf_key_size];
	if( ((t->k_prf = (unsigned char*) malloc(cNewParams.prf_key_size)) == NULL)) goto cleanup;
	if( ((t->alpha = (BIGNUM**) malloc(sizeof(BIGNUM *) * cNewParams.num_sectors)) == NULL)) goto cleanup;
	memset(t->alpha, 0, sizeof(BIGNUM *) * cNewParams.num_sectors);	
	for(i = 0; i < cNewParams.num_sectors; i++){
		t->alpha[i] = BN_new();
	}
	
	return t;

cleanup:
	destroy_cpor_t(t);
	return NULL;
	
}


CPOR_tag *allocate_cpor_tag(){

	CPOR_tag *tag = NULL;
	
	if( ((tag = (CPOR_tag*)malloc(sizeof(CPOR_tag))) == NULL)) return NULL;
	memset(tag, 0, sizeof(CPOR_tag));
	if( ((tag->sigma = BN_new()) == NULL)) goto cleanup;
	tag->index = 0;
	
	return tag;
	
cleanup:
	if(tag) destroy_cpor_tag(tag);
	return NULL;
	
}

CPOR_key *allocate_cpor_key(unsigned int enc_key_size, unsigned int mac_key_size){

	// CPOR_key *key = new CPOR_key{};
  CPOR_key *key = NULL;
	if( ((key = (CPOR_key *)malloc(sizeof(CPOR_key))) == NULL)) goto cleanup;
  // key->k_enc = new unsigned char[enc_key_size];
	if( ((key->k_enc = (unsigned char*) malloc(cNewParams.enc_key_size)) == NULL)) goto cleanup;
	key->k_enc_size = enc_key_size;
  // key->k_mac = new unsigned char[mac_key_size];
	if( ((key->k_mac = (unsigned char*) malloc(cNewParams.enc_key_size)) == NULL)) goto cleanup;
	key->k_mac_size = mac_key_size;
	key->global = NULL;
	
	return key;
	
cleanup:
	if(key) destroy_cpor_key(key);
	return NULL;
	
}



CPOR_global *allocate_cpor_global(){

	CPOR_global *global = NULL;
	
  // global = new CPOR_global();
	if( ((global = (CPOR_global *) malloc(sizeof(CPOR_global))) == NULL)) return NULL;
	if( ((global->Zp = BN_new()) == NULL)) goto cleanup;

	return global;
	
cleanup:
	destroy_cpor_global(global);
	return NULL;
}

CPOR_challenge *allocate_cpor_challenge(unsigned int l){
	
	CPOR_challenge *challenge = NULL;
	int i = 0;

	if( ((challenge = (CPOR_challenge*)malloc(sizeof(CPOR_challenge))) == NULL)) return NULL;
	memset(challenge, 0, sizeof(CPOR_challenge));
	challenge->l = l;
	if( ((challenge->I = (unsigned int*)malloc(sizeof(unsigned int) * challenge->l)) == NULL)) goto cleanup;
	memset(challenge->I, 0, sizeof(unsigned int) * challenge->l);
	if( ((challenge->nu = (BIGNUM**)malloc(sizeof(BIGNUM *) * challenge->l)) == NULL)) goto cleanup;	
	memset(challenge->nu, 0, sizeof(BIGNUM *) * challenge->l);
	for(i = 0; i < challenge->l; i++)
		if( ((challenge->nu[i] = BN_new()) == NULL)) goto cleanup;
	if( ((challenge->global = allocate_cpor_global()) == NULL)) goto cleanup;

	return challenge;
	
cleanup:
	destroy_cpor_challenge(challenge);
	return NULL;
}

CPOR_proof *allocate_cpor_proof(){

	CPOR_proof *proof = NULL;
	int i = 0;
		
	if( ((proof = (CPOR_proof*) malloc(sizeof(CPOR_proof))) == NULL)) return NULL;
	memset(proof, 0, sizeof(CPOR_proof));
	if( ((proof->sigma = BN_new()) == NULL )) goto cleanup;
	if( ((proof->mu = (BIGNUM**) malloc(sizeof(BIGNUM *) * cNewParams.num_sectors)) == NULL)) goto cleanup;
	memset(proof->mu, 0, sizeof(BIGNUM *) * cNewParams.num_sectors);
	for(i = 0; i < cNewParams.num_sectors; i++)
		if( ((proof->mu[i] = BN_new()) == NULL)) goto cleanup;

	return proof;

cleanup:
	destroy_cpor_proof(proof);
	return NULL;	

	
}

void sfree(void *ptr, size_t size){ memset(ptr, 0, size); free(ptr); ptr = NULL;}

int get_rand_range(unsigned int min, unsigned int max, unsigned int *value){
	unsigned int rado;
	unsigned int range = max - min + 1;
	
	if(!value) return 0;
	if(max < min) return 0;
	do{
		if(!RAND_bytes((unsigned char *)&rado, sizeof(unsigned int))) return 0;
	}while(rado > UINT_MAX - (UINT_MAX % range));
	
	*value = min + (rado % range);
	
	return 1;
}

CPOR_t *cpor_create_t(CPOR_global *global, unsigned int n, 
		unsigned int prf_key_size, unsigned int num_sectors){

	CPOR_t *t = NULL;
	int i = 0;
	

	if( ((t = allocate_cpor_t()) == NULL)) return NULL;

	/* Generate a random PRF key, k_prf */
	if(!RAND_bytes(t->k_prf, sizeof(t->k_prf))) return NULL;

	for(i = 0; i < num_sectors; i++){
		if(!BN_rand_range(t->alpha[i], global->Zp)) return NULL;
  }
	
	t->n = n;
	
	return t;
	
// cleanup:
// 	if(t) destroy_cpor_t(t);
// 	return NULL;
}

void destroy_cpor_tag(CPOR_tag *tag){

	if(!tag) return;
	if(tag->sigma) BN_clear_free(tag->sigma);
	sfree(tag, sizeof(CPOR_tag));
	tag = NULL;
}

CPOR_tag *cpor_tag_block(CPOR_global *global, unsigned char *k_prf, BIGNUM **alpha, unsigned char *block, size_t blocksize, unsigned int index){

	CPOR_tag *tag = NULL;
	BN_CTX * ctx = NULL;
	BIGNUM *prf_i = NULL;
	BIGNUM *message = NULL;
	BIGNUM *product = NULL;
	BIGNUM *sum = NULL;
	int j = 0;
	// std::cout << "CPORTAGBLOCK" << std::endl;
	if(!global || !block || !blocksize || !alpha || !k_prf) return NULL;
	
	if(!global->Zp) return NULL;
	
	/* Allocate memory */
	if( ((tag = allocate_cpor_tag()) == NULL)) goto cleanup;
	if( ((ctx = BN_CTX_new()) == NULL)) goto cleanup;
	if( ((message = BN_new()) == NULL)) goto cleanup;
	if( ((product = BN_new()) == NULL)) goto cleanup;
	if( ((sum = BN_new()) == NULL)) goto cleanup;
	
	/* compute PRF_k(i) */
	if( ((prf_i = generate_prf_i(k_prf, index)) == NULL)) goto cleanup;
	
	BN_clear(sum);
	/* Sum all alpha * sector products */
	for(j = 0; j < cNewParams.num_sectors; j++){
		size_t sector_size = 0;
		unsigned char *sector = block + (j * cNewParams.sector_size);

		if( (blocksize - (j * cNewParams.sector_size)) > cNewParams.sector_size)
			sector_size = cNewParams.sector_size;
		else
			sector_size = (blocksize - (j * cNewParams.sector_size));
		
		/* Convert the sector into a BIGNUM */
		if(!BN_bin2bn(sector, sector_size, message)) goto cleanup;

		/* Check to see if the message is still an element of Zp */
		if(BN_ucmp(message, global->Zp) == 1) goto cleanup;

		/* multiply alpha and m */
		if(!BN_mod_mul(product, alpha[j], message, global->Zp, ctx)) goto cleanup;
		
		/* Sum the alpha_j-sector_ij products together */
		if(!BN_mod_add(sum, product, sum, global->Zp, ctx)) goto cleanup;
		
	}
	
	/* add alpha*m and PRF_k(i) mod p to make it an element of Z_p */
    if(!BN_mod_add(tag->sigma, prf_i, sum, global->Zp, ctx)) goto cleanup;

	/* Set the index */
	tag->index = index;
	
	/* We're done, cleanup and return tag */
	if(prf_i) BN_clear_free(prf_i);
	if(message) BN_clear_free(message);
	if(product) BN_clear_free(product);	
	if(sum) BN_clear_free(sum);	
	if(ctx) BN_CTX_free(ctx);
	
	return tag;

cleanup:
	if(tag) destroy_cpor_tag(tag);
	if(prf_i) BN_clear_free(prf_i);
	if(message) BN_clear_free(message);
	if(product) BN_clear_free(product);	
	if(sum) BN_clear_free(sum);
	if(ctx) BN_CTX_free(ctx);
	
	return NULL;
}

CPOR_challenge *cpor_challenge_file(std::string hash, CPOR_key* pkey){


	CPOR_challenge *challenge = NULL;
	FILE *tfile = NULL;
	CPOR_t *t = NULL;
	
	/* Open the t file for reading */
  fs::path path = GetDataDir() / "cpor" / "Tfiles" / hash.append(".t");
	// std::cout <<"T path:"<<path <<std::endl;
	tfile = fsbridge::fopen(path, "r");
	if(!tfile){
		goto cleanup;
	}
	

	
	/* Get t for n (the number of blocks) */
	// t = read_cpor_t(tfile, pkey);
	t = UnserializeT(readFileToUnsignedChar(path.string()));
  // std::cout << "Read t cmp" <<std::endl;
	if(!t){ fprintf(stderr, "Could not get t.\n"); goto cleanup; }

	challenge = cpor_create_challenge(pkey->global, t->n);
  // std::cout << "Create challenge is cmp" <<std::endl;
	if(!challenge) goto cleanup;

	if(tfile) fclose(tfile);
	if(t) destroy_cpor_t(t);
	// std::cout <<"Challenge cmp :" << BN_bn2hex(challenge->global->Zp) <<std::endl;
	return challenge;
cleanup:
	// if(pkey) destroy_cpor_key(pkey);
	if(tfile) fclose(tfile);
	if(t) destroy_cpor_t(t);
	return NULL;
	
}


static int write_cpor_tag(FILE *tagfile, CPOR_tag *tag){
	
	unsigned char *sigma = NULL;
	size_t sigma_size = 0;
	
	if(!tagfile || !tag) return 0;
	
	/* Write sigma (size of sigma, then sigma itself) */
	sigma_size = BN_num_bytes(tag->sigma);
	fwrite(&sigma_size, sizeof(size_t), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;
	if( ((sigma = (unsigned char*) malloc(sigma_size)) == NULL)) goto cleanup;
	memset(sigma, 0, sigma_size);
	if(!BN_bn2bin(tag->sigma, sigma)) goto cleanup;
	fwrite(sigma, sigma_size, 1, tagfile);
	if(ferror(tagfile)) goto cleanup;
	
	/* write index */
	fwrite(&(tag->index), sizeof(unsigned int), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;	
	
	if(sigma) sfree(sigma, sigma_size);
		
	return 1;
	
cleanup:
	if(sigma) sfree(sigma, sigma_size);
	return 0;
}

static CPOR_tag *read_str_cpor_tag(std::vector<unsigned char> tagfile, unsigned int index){

	CPOR_tag *tag = NULL;
	size_t sigma_size = 0;
	unsigned char *sigma = NULL;
	int i = 0;

  unsigned char* cTagFile = &tagfile[0];

  // strcpy(cTagFile, tagfile.c_str());
	
	/* Allocate memory */
	if( ((tag = allocate_cpor_tag()) == NULL)) return NULL;
	
  unsigned int offset = 0;
	/* Seek to tag offset index */
	for(i = 0; i < index; i++){
		// fread(&sigma_size, sizeof(size_t), 1, tagfile);
    memcpy(&sigma_size, cTagFile + offset, sizeof(size_t));
    offset += sizeof(size_t) + sigma_size + sizeof(unsigned int);
		// if(fseek(tagfile, (sigma_size + sizeof(unsigned int)), SEEK_CUR) < 0) goto cleanup;
	}
	
	/* Read in the sigma we're looking for */
	// fread(&sigma_size, sizeof(size_t), 1, tagfile);
    memcpy(&sigma_size, cTagFile + offset, sizeof(size_t));
  offset += sizeof(size_t);
	// if(ferror(tagfile)) goto cleanup;
	if( ((sigma = (unsigned char*)malloc(sigma_size)) == NULL)) return NULL;
	memset(sigma, 0, sigma_size);
  memcpy(sigma,cTagFile+offset, sigma_size);
  offset += sigma_size;
	
	// fread(sigma, sigma_size, 1, tagfile);
	// if(ferror(tagfile)) goto cleanup;
	if(!BN_bin2bn(sigma, sigma_size, tag->sigma)) return NULL;

	/* read index */
  memcpy(&(tag->index),cTagFile + offset, sizeof(unsigned int));
	// fread(&(tag->index), sizeof(unsigned int), 1, tagfile);
	// if(ferror(tagfile)) goto cleanup;
	
	if(sigma) sfree(sigma, sigma_size);
	
	return tag;
	
// cleanup:
// 	if(sigma) sfree(sigma, sigma_size);
// 	if(tag) destroy_cpor_tag(tag);
	
// 	return NULL;
}

CPOR_tag *read_cpor_tag(FILE *tagfile, unsigned int index){

	CPOR_tag *tag = NULL;
	size_t sigma_size = 0;
	unsigned char *sigma = NULL;
	int i = 0;

	if(!tagfile) return NULL;
	
	/* Allocate memory */
	if( ((tag = allocate_cpor_tag()) == NULL)) goto cleanup;
	
	/* Seek to start of tag file */
	if(fseek(tagfile, 0, SEEK_SET) < 0) goto cleanup;
	
	/* Seek to tag offset index */
	for(i = 0; i < index; i++){
		fread(&sigma_size, sizeof(size_t), 1, tagfile);
		if(ferror(tagfile)) goto cleanup;
		if(fseek(tagfile, (sigma_size + sizeof(unsigned int)), SEEK_CUR) < 0) goto cleanup;
	}
	
	/* Read in the sigma we're looking for */
	fread(&sigma_size, sizeof(size_t), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;
	if( ((sigma = (unsigned char *)malloc(sigma_size)) == NULL)) goto cleanup;
	memset(sigma, 0, sigma_size);
	fread(sigma, sigma_size, 1, tagfile);
	if(ferror(tagfile)) goto cleanup;
	if(!BN_bin2bn(sigma, sigma_size, tag->sigma)) goto cleanup;
	
	/* read index */
	fread(&(tag->index), sizeof(unsigned int), 1, tagfile);
	if(ferror(tagfile)) goto cleanup;
	
	if(sigma) sfree(sigma, sigma_size);
	
	return tag;
	
cleanup:
	if(sigma) sfree(sigma, sigma_size);
	if(tag) destroy_cpor_tag(tag);
	
	return NULL;
}


size_t get_ciphertext_size(size_t plaintext_len){

	size_t block_size = 0;

	EVP_CIPHER_CTX* ctx;
	ctx = EVP_CIPHER_CTX_new();
	if(!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL)) return 0;
	block_size = EVP_CIPHER_CTX_block_size(ctx);
	EVP_CIPHER_CTX_free(ctx);
		
	return plaintext_len + block_size;
}

static int write_cpor_t(FILE *tfile, CPOR_key *key, CPOR_t *t){
	
	unsigned char *enc_input = NULL;
	unsigned char *tbytes = NULL;
	unsigned char *t0 = NULL;
	unsigned char *t0_mac = NULL;
	unsigned char *alpha = NULL;
	size_t enc_input_size = 0;
	size_t tbytes_size = 0;
	size_t t0_size = 0;
	size_t t0_mac_size = 0;
	size_t alpha_size = 0;
	int i = 0;
	
	if(!tfile || !key || !t) return 0;

	/* Prepare to encrypt k_prf and alphas */ 
	enc_input_size = cNewParams.prf_key_size;
	if( ((enc_input =(unsigned char*) malloc(enc_input_size)) == NULL)) goto cleanup;
	memcpy(enc_input, t->k_prf, cNewParams.prf_key_size);

	for(i=0; i < cNewParams.num_sectors; i++){
		alpha_size = BN_num_bytes(t->alpha[i]);
		if( ((alpha = (unsigned char*)malloc(alpha_size)) == NULL)) goto cleanup;
		memset(alpha, 0, alpha_size);
		if(!BN_bn2bin(t->alpha[i], alpha)) goto cleanup;
		enc_input_size += sizeof(size_t) + alpha_size;
		if( ((enc_input = (unsigned char*)realloc(enc_input, enc_input_size)) == NULL)) goto cleanup;
		memcpy(enc_input + (enc_input_size - alpha_size - sizeof(size_t)), &alpha_size, sizeof(size_t));
		memcpy(enc_input + (enc_input_size - alpha_size), alpha, alpha_size);
		sfree(alpha, alpha_size);
	}

	/* t0_size is the size of our index, n, plus the resulting ciphertext */
	t0_size = sizeof(unsigned int) + get_ciphertext_size(enc_input_size);
	if( ((t0 = (unsigned char*)malloc(t0_size)) == NULL)) goto cleanup;
	memset(t0, 0, t0_size);
	/* Copy the number of blocks in the file into t0 */
	memcpy(t0, &(t->n), sizeof(unsigned int));
	
	t0_mac_size = EVP_MAX_MD_SIZE;
	if( ((t0_mac = (unsigned char*)malloc(t0_mac_size)) == NULL)) goto cleanup;
	memset(t0_mac, 0, t0_mac_size);
	/* Encrypt and authenticate k_prf and alphas */
	if(!encrypt_and_authentucate_secrets(key, enc_input, enc_input_size, t0 + sizeof(unsigned int), &t0_size, t0_mac, &t0_mac_size))
		goto cleanup;
	/* Adjust size to account for index */
	t0_size += sizeof(unsigned int);


	/* Create t */
	tbytes_size = t0_size + sizeof(size_t) + t0_mac_size + sizeof(size_t);
	if( ((tbytes =(unsigned char*) malloc(tbytes_size)) == NULL)) goto cleanup;
	memcpy(tbytes, &t0_size, sizeof(size_t));
	memcpy(tbytes + sizeof(size_t), t0, t0_size);
	memcpy(tbytes + sizeof(size_t) + t0_size, &t0_mac_size, sizeof(size_t));
	memcpy(tbytes + sizeof(size_t) + t0_size + sizeof(size_t), t0_mac, t0_mac_size);

	fwrite(&tbytes_size, sizeof(size_t), 1, tfile);
	if(ferror(tfile)) goto cleanup;
	fwrite(tbytes, tbytes_size, 1, tfile);
	if(ferror(tfile)) goto cleanup;
	
	if(enc_input) sfree(enc_input, enc_input_size);
	if(tbytes) sfree(tbytes, tbytes_size);
	if(t0) sfree(t0, t0_size);
	if(t0_mac) sfree(t0_mac, t0_mac_size);
	
	return 1;
	
cleanup:
	if(enc_input) sfree(enc_input, enc_input_size);
	if(tbytes) sfree(tbytes, tbytes_size);
	if(t0) sfree(t0, t0_size);
	if(t0_mac) sfree(t0_mac, t0_mac_size);

	return 0;
}



CPOR_global *cpor_create_global(unsigned int bits){

	CPOR_global *global = NULL;
	BN_CTX *ctx = NULL;
	
	if(!bits) return NULL;
	
	if( ((global = allocate_cpor_global()) == NULL)) goto cleanup;
	if( ((ctx = BN_CTX_new()) == NULL)) goto cleanup;
		
	/* Generate a bits-sized safe prime for our group Zp */
	if(!BN_generate_prime(global->Zp, bits, 1, NULL, NULL, NULL, NULL)) goto cleanup;
	/* Check to see it's prime afterall */
	if(!BN_is_prime(global->Zp, BN_prime_checks, NULL, ctx, NULL)) goto cleanup;

	if(ctx) BN_CTX_free(ctx);
		
	return global;
	
cleanup:
	if(global) destroy_cpor_global(global);
	if(ctx) BN_CTX_free(ctx);
	return NULL;
}

void write_cpor_t_without_key(CPOR_t* t, FILE* tfile) {
  std::vector<unsigned char> t_bin = SerializeT(t);
	unsigned char* p_t_bin = &t_bin[0];
	fwrite(p_t_bin, t_bin.size(), 1, tfile);
}



int local_cpor_tag_file(std::string str, uint256 hash, CPOR_key* pkey){

	CPOR_key *key = NULL;
	CPOR_t *t = NULL;
	const char *file = str.c_str();
	FILE *tagfile = NULL;
	FILE *tfile = NULL;
	unsigned int numfileblocks = 0;
	unsigned int index = 0;


  fs::path cporpath = GetDataDir() / "cpor";
  fs::create_directory(cporpath);
    fs::path tagfilepath = cporpath / "Tags";
    fs::create_directory(tagfilepath);
    tagfilepath /= hash.ToString().append(".tag");
    fs::path tfilepath = cporpath / "Tfiles";
    fs::create_directory(tfilepath);
    tfilepath /= hash.ToString().append(".t");
	// struct stat st;
    unsigned int size = (unsigned int)str.length();
    // if(str.length()%8) size++;
  // std::cout << "String length" << size << std::endl;
	unsigned char buf[cNewParams.block_size];
	CPOR_tag *tag = NULL;
	// TODO: local handle tag and t file
    
	// /* If no tag file path is specified, add a .tag extension to the filepath */
	// if(!tagfilepath && (filepath_len < MAXPATHLEN - 5)){
	// 	if( snprintf(realtagfilepath, MAXPATHLEN, "%s.tag", filepath) >= MAXPATHLEN ) return -1;
	// }else{
	// 	memcpy(realtagfilepath, tagfilepath, tagfilepath_len);
	// }
	
	// /* If no t file path is specified, add a .t extension to the filepath */
	// if(!tfilepath && (filepath_len < MAXPATHLEN - 3)){
	// 	if( snprintf(realtfilepath, MAXPATHLEN, "%s.t", filepath) >= MAXPATHLEN ) return -1;
	// }else{
	// 	memcpy(realtfilepath, tfilepath, tfilepath_len);
	// }

	tagfile = fsbridge::fopen(tagfilepath, "w");
    
	if(!tagfile) return -1;
  if(!fs::exists(tfilepath)){
	  tfile = fsbridge::fopen(tfilepath, "w");
	  if(!tfile) return -1;
    /* Calculate the number cpor blocks in the file */
    numfileblocks = (size/cNewParams.block_size);
    if(size%cNewParams.block_size) numfileblocks++;

    /* Generate the per-file secrets */
	  t = cpor_create_t(pkey->global, numfileblocks, cNewParams.prf_key_size, cNewParams.num_sectors);
  } else {
    t = UnserializeT(readFileToUnsignedChar(tfilepath.c_str()));
  }

	
	

	

  if(!t) return -1;


	// /* Open the file for reading */
	// file = fopen(filepath, "r");
	// if(!file){
	// 	fprintf(stderr, "ERROR: Was not able to open %s for reading.\n", filepath);
	// 	goto cleanup;
	// }

    
    int fileIndex = 0;
  // LogPrintf("Start writing file\n");
	do{
		memset(buf, 0, cNewParams.block_size);
    // std::cout << "FileIndex: " << fileIndex << std::endl;
    
    if(fileIndex + cNewParams.block_size > size) {
      memcpy(buf, str.substr(fileIndex).c_str(), str.substr(fileIndex).length());
    } else {
      memcpy(buf, str.substr(fileIndex, cNewParams.block_size).c_str(), cNewParams.block_size);
    }
    fileIndex += cNewParams.block_size;
    // LogPrintf("Tag File: blocksize: %d\n",cNewParams.block_size);

		tag = cpor_tag_block(pkey->global, t->k_prf, t->alpha, buf, cNewParams.block_size, index);
    // LogPrintf("Tag File: cmp\n");
		
    if(!write_cpor_tag(tagfile, tag)) return -1;
		index++;
		destroy_cpor_tag(tag);
	}while(fileIndex < size);


	/* Write t to the tfile */
	// if(!write_cpor_t(tfile, pkey, t)) return -1;
	write_cpor_t_without_key(t,tfile);
  // LogPrintf("Finalize\n");
	destroy_cpor_t(t);
	// if(file) fclose(file);
	delete(file);
	if(tagfile) fclose(tagfile);
	if(tfile) fclose(tfile);
	return 1;
	
}

CPOR_challenge *cpor_create_challenge(CPOR_global *global, unsigned int n){

	CPOR_challenge *challenge;
	int i = 0;
	unsigned int l;
	unsigned int *random_indices = NULL;
	unsigned int tmp = 0;
	unsigned int swapwith = 0;
	
	if(!global || !n) return NULL;
	if(!global->Zp) return NULL;
	
	/* Set l, the number of challenge blocks. */
	if(n > cNewParams.num_challenge)
		l = cNewParams.num_challenge;
	else
		l = n;
	

	/* Allocate memory */
	if( ((challenge = allocate_cpor_challenge(l)) == NULL)) goto cleanup;
	
	/* Randomly choose l indices (without replacement) */
	/* To do this, we create an array with all indices 0 - n-1, shuffle it, and take the first l values */
	if( ((random_indices = (unsigned int*) malloc(sizeof(unsigned int) * n)) == NULL)) goto cleanup;
	for(i = 0; i < n; i++)
		random_indices[i] = i;
	for(i = 0; i < n; i++){
		get_rand_range(0, n-1, &swapwith);
		tmp = random_indices[swapwith];
		random_indices[swapwith] = random_indices[i];
		random_indices[i] = tmp;
	}
	for(i = 0; i < l; i++){
		challenge->I[i] = random_indices[i];
	}

	sfree(random_indices, sizeof(unsigned int) * n);
	
	/* Randomly choose l elements of Zp (with replacement) */
	for(i = 0; i < l; i++)
		if(!BN_rand_range(challenge->nu[i], global->Zp)) goto cleanup;
	
	/* Set the global */
	if(!BN_copy(challenge->global->Zp, global->Zp)) goto cleanup;
	
	return challenge;
	
cleanup:
	if(challenge) destroy_cpor_challenge(challenge);
	if(random_indices) sfree(random_indices, sizeof(unsigned int) * n);
	
	return NULL;
}

void destroy_cpor_challenge(CPOR_challenge *challenge){

	int i;

	if(!challenge) return;
	if(challenge->I) sfree(challenge->I, sizeof(unsigned int) * challenge->l);
	if(challenge->nu){
		for(i = 0; i < challenge->l; i++){
			if(challenge->nu[i]) BN_clear_free(challenge->nu[i]);
		}
		sfree(challenge->nu, sizeof(BIGNUM *) * challenge->l);
	}
	challenge->l = 0;
	if(challenge->global) destroy_cpor_global(challenge->global);
	sfree(challenge, sizeof(CPOR_challenge));
	
	return;
}

int decrypt_and_verify_secrets(CPOR_key *key, unsigned char *input, size_t input_len, unsigned char *plaintext, size_t *plaintext_len, unsigned char *authenticator, size_t authenticator_len){

	EVP_CIPHER_CTX* ctx;
	EVP_CIPHER *cipher = NULL;
	unsigned char mac[EVP_MAX_MD_SIZE];
	size_t mac_size = EVP_MAX_MD_SIZE;
	int len;
	
	if(!key || !key->k_enc || !key->k_mac || !input || !input_len || !plaintext || !plaintext_len || !authenticator || !authenticator_len) return 0; 
	
	OpenSSL_add_all_algorithms();
	memset(mac, 0, mac_size);
	
	/* Verify the HMAC-SHA1 */
	if(!HMAC(EVP_sha1(), key->k_mac, key->k_mac_size, input, input_len, mac, (unsigned int *)&mac_size)) goto cleanup;
	if(authenticator_len != mac_size) goto cleanup;
	if(memcmp(mac, authenticator, mac_size) != 0) goto cleanup;
	
	
	ctx = EVP_CIPHER_CTX_new();
	switch(key->k_enc_size){
		case 16:
			cipher = (EVP_CIPHER *)EVP_aes_128_cbc();
			break;
		case 24:
			cipher = (EVP_CIPHER *)EVP_aes_192_cbc();
			break;
		case 32:
			cipher = (EVP_CIPHER *)EVP_aes_256_cbc();
			break;
		default:
			return 0;
	}
	if(!EVP_DecryptInit(ctx, cipher, key->k_enc, NULL)) goto cleanup;
	
	*plaintext_len = 0;
	
	if(!EVP_DecryptUpdate(ctx, plaintext, (int *)plaintext_len, input, input_len)) goto cleanup;
	EVP_DecryptFinal(ctx, plaintext + *plaintext_len, &len);
	
	*plaintext_len += len;
	
	EVP_CIPHER_CTX_free(ctx);
	
	return 1;

cleanup:
	*plaintext_len = 0;

	return 0;
	
}

std::vector<unsigned char> SerializeChallenge(CPOR_challenge* challenge) {
  int zp_char_size = BN_num_bytes(challenge->global->Zp);
  unsigned char* zp_char = new unsigned char[zp_char_size];

  unsigned int size = zp_char_size + sizeof(unsigned int) * 2 + sizeof(int);
  for(int i =0;i<challenge->l;++i){
    size += BN_num_bytes(challenge->nu[i]) + sizeof(int) + sizeof(unsigned int);
  }

  unsigned char* result = (unsigned char*) malloc(size);
  unsigned char* head = result;
  unsigned int offset = 0;

  memset(result, 0, sizeof(head));

  //Serialize l
  memcpy(result,&(challenge->l),sizeof(unsigned int));

  offset += sizeof(unsigned int);

  //Serialize I
	for(int i = 0; i < challenge->l; ++i) {
		memcpy(result+offset, &challenge->I[i], sizeof(unsigned int));
		// std::cout << "I" << *((challenge->I) + i) <<std::endl;
		offset += sizeof(unsigned int);
	}
  

  //Serialize Zp char size
  memcpy(result + offset, &zp_char_size, sizeof(int));
  
  offset += sizeof(int);

  //Serialize Zp char
  BN_bn2bin(challenge->global->Zp, zp_char);
  memcpy(result + offset, zp_char, zp_char_size);

  offset += zp_char_size;

  //Serialize nu
  for(int i =0;i<challenge->l;++i){
    
    int nuSize = BN_num_bytes(challenge->nu[i]);
    unsigned char* nu_char = new unsigned char[nuSize];
    BN_bn2bin(challenge->nu[i], nu_char);

    memcpy(result + offset, &nuSize,sizeof(int));

    offset += sizeof(int);
    memcpy(result + offset, nu_char ,nuSize);
		delete(nu_char);
    offset += nuSize;
  }
	delete(zp_char);
  // fwrite(s.c_str(),s.length(),1,f);
	std::vector<unsigned char> vResult(result, result + size);
	free(result);
  return vResult;

  
}

CPOR_challenge* UnserializeChallenge(std::vector<unsigned char>& from) {
  
  unsigned char* pfrom = &from[0];
	unsigned char* zp_char;
  unsigned int offset = 0;

	unsigned int l;
	unsigned int I;
	int zp_size;
	// std::cout << "Serialize challenge start" <<std::endl;

	memcpy(&l, pfrom, sizeof(unsigned int));
	offset += sizeof(unsigned int);

  CPOR_challenge* newChallenge = allocate_cpor_challenge(l);
	newChallenge->l = l;
	// std::cout << "l:" << newChallenge->l <<std::endl;

	for(int i = 0; i < newChallenge->l; ++i) {
		memcpy(&I, pfrom + offset, sizeof(unsigned int));
		newChallenge->I[i] = I;
		offset += sizeof(unsigned int);
	}
	
  memcpy(&zp_size, pfrom + offset ,sizeof(int));
	zp_char = new unsigned char[zp_size];
	// std::cout << "ZPs:" << zp_size <<std::endl;
	offset += sizeof(int);

	memcpy(zp_char, pfrom + offset, zp_size);
	BN_bin2bn(zp_char, zp_size, newChallenge->global->Zp);
  offset += zp_size;
	// std::cout << "ZP:" << zp_char <<std::endl;
	// std::cout << "ZP cmp" << std::endl;
  for(int i =0;i<newChallenge->l;++i){

		int bigNumSize;
    memcpy(&bigNumSize,pfrom+offset,sizeof(int));
    offset += sizeof(int);

		unsigned char* nu_char = new unsigned char[bigNumSize];
    memcpy( nu_char, pfrom + offset, bigNumSize);
		BN_bin2bn(nu_char, bigNumSize, newChallenge->nu[i]);
    offset += bigNumSize;
    delete [] nu_char;
  }
  // free(pfrom);
  // free(zp_char);
  delete [] zp_char;
	// std::cout << "Unserialize Challenge cmp" <<std::endl;
  return newChallenge;
  
}

CPOR_proof *cpor_create_proof_final(CPOR_proof *proof){

	return proof;
}

/* For each message index i, call update (we're going to call this challenge->l times */
CPOR_proof *cpor_create_proof_update(CPOR_challenge *challenge, CPOR_proof *proof, CPOR_tag *tag, unsigned char *block, size_t blocksize, unsigned int index, unsigned int i){

	BN_CTX * ctx = NULL;
	BIGNUM *message = NULL;
	BIGNUM *product = NULL;
	int j = 0;	
	
	if(!challenge || !tag || !block) goto cleanup;
	
	if(!proof)
		if( ((proof = allocate_cpor_proof()) == NULL)) goto cleanup;
	if( ((ctx = BN_CTX_new()) == NULL)) goto cleanup;
	if( ((message = BN_new()) == NULL)) goto cleanup;
	if( ((product = BN_new()) == NULL)) goto cleanup;
	
	/* Calculate and update the mu's */	
	for(j = 0; j < cNewParams.num_sectors; j++){
		size_t sector_size = 0;
		unsigned char *sector = block + (j * cNewParams.sector_size);

		if( (blocksize - (j * cNewParams.sector_size)) > cNewParams.sector_size)
			sector_size = cNewParams.sector_size;
		else
			sector_size = (blocksize - (j * cNewParams.sector_size));

		/* Convert the sector into a BIGNUM */
		if(!BN_bin2bn(sector, (unsigned int)sector_size, message)) goto cleanup;

		/* Check to see if the message is still an element of Zp */
		if(BN_ucmp(message, challenge->global->Zp) == 1) goto cleanup;

		/* multiply nu_i and m_ij */
		if(!BN_mod_mul(product, challenge->nu[i], message, challenge->global->Zp, ctx)) goto cleanup;

		/* Sum the nu_i-m_ij products together */
		if(!BN_mod_add(proof->mu[j], proof->mu[j], product, challenge->global->Zp, ctx)) goto cleanup;
		
	}
	
	/* Calculate sigma */
	/* multiply nu_i (challenge) and sigma_i (tag) */
	if(!BN_mod_mul(product, challenge->nu[i], tag->sigma, challenge->global->Zp, ctx)) goto cleanup;

	/* Sum the nu_i-sigma_i products together */
	if(!BN_mod_add(proof->sigma, proof->sigma, product, challenge->global->Zp, ctx)) goto cleanup;
	
	if(message) BN_clear_free(message);
	if(product) BN_clear_free(product);	
	if(ctx) BN_CTX_free(ctx);
	
	return proof;

cleanup:
	if(proof) destroy_cpor_proof(proof);
	if(message) BN_clear_free(message);
	if(product) BN_clear_free(product);
	if(ctx) BN_CTX_free(ctx);
		
	return NULL;
}


/**
 * @brief Generate proof from str and TagFile
 * 
 * @param file 
 * @param tagfile 
 * @param challenge 
 * @return CPOR_proof* 
 */
CPOR_proof *cpor_prove_file(std::string& strfile, std::vector<unsigned char>& tagfile, CPOR_challenge *challenge){

	CPOR_tag *tag = NULL;
	CPOR_proof *proof = NULL;

	unsigned char* block = new unsigned char[cNewParams.block_size];
	int i = 0;
  char* charFile = new char[strfile.length()+1];
  strcpy(charFile, strfile.c_str());
	
	memset(block, 0, cNewParams.block_size);
  
	// std::cout << "sizeof I: " << sizeof(challenge->I)/sizeof(unsigned int) <<std::endl;
	for(i = 0; i < challenge->l; i++){
		unsigned int offset = 0;
		memset(block, 0, cNewParams.block_size);

		/* Seek to data block at I[i] */
		// if(fseek(file, (cNewParams.block_size * (challenge->I[i])), SEEK_SET) < 0) goto cleanup;
		std::cout << challenge->I[i] <<std::endl;
		offset += cNewParams.block_size * (challenge->I[i]);
		if(offset + cNewParams.block_size > strlen(strfile.c_str())) {
			memcpy(block, charFile + offset , strlen(strfile.c_str()) - offset);

		} else {
			memcpy(block, charFile + offset ,cNewParams.block_size );

		}

    
		
    
		/* Read tag for data block at I[i] */
		tag = read_str_cpor_tag(tagfile, challenge->I[i]);
		// std::cout << "TagIndex" << tag->index <<std::endl;
		if(!tag) goto cleanup;
		
		proof = cpor_create_proof_update(challenge, proof, tag, block, cNewParams.block_size, challenge->I[i], i);
		if(!proof) goto cleanup;
		
		destroy_cpor_tag(tag);
		
	}
	
	// std::cout <<"success" <<std::endl;
	proof = cpor_create_proof_final(proof);
	delete [] block;
	delete [] charFile;
	// if(tag) destroy_cpor_tag(tag);

	// destroy_cpor_challenge(challenge);
	// if(file) fclose(file);
	// if(tagfile) fclose(tagfile);

	return proof;

cleanup:
	// if(tagfile) fclose(tagfile);
	if(tag) destroy_cpor_tag(tag);

	return NULL;
}

std::vector<unsigned char> SerializeProof(CPOR_proof* proof) {
  unsigned int size = sizeof(int) + BN_num_bytes(proof->sigma);
  for(int i =0;i<cNewParams.num_sectors;++i){
    size += BN_num_bytes(proof->mu[i]) + sizeof(int);
  }

  char* result = new char[size+1];
  unsigned int offset = 0;
  // std::cout << "SerializeProof..." <<std::endl;

  int bigNumSize = BN_num_bytes(proof->sigma);
  memcpy(result, &bigNumSize,sizeof(int));
  offset += sizeof(int);
  //TODO:Must use BN_bn2bin to serialize
  
  unsigned char* sigma_char = new unsigned char[bigNumSize];
  BN_bn2bin( proof->sigma, sigma_char);
  memcpy(result+offset,sigma_char,bigNumSize);
  offset += bigNumSize;

  for(int i =0;i<cNewParams.num_sectors;++i){

		int nSize = BN_num_bytes(proof->mu[i]);
    memcpy(result + offset, &nSize,sizeof(int));
    offset += sizeof(int);

    unsigned char* mu_char = new unsigned char[nSize];
    BN_bn2bin(proof->mu[i], mu_char);
    memcpy(result + offset, mu_char,nSize);
    offset += nSize;
    delete [] mu_char;
  }
  delete [] sigma_char;
	// destroy_cpor_proof(proof);
  std::vector<unsigned char> resultV(result, result + size);
  delete [] result;
  return resultV;
  
}

CPOR_proof* UnserializeProof(std::vector<unsigned char> from) {

  unsigned char* pfrom = &from[0];
  unsigned int offset = 0;
  CPOR_proof* newProof = allocate_cpor_proof();

  int bigNumSize;
  memcpy(&bigNumSize,pfrom+offset,sizeof(int));
  offset += sizeof(int);

  unsigned char* sigma_char = new unsigned char[bigNumSize];
  memcpy(sigma_char,pfrom+offset,bigNumSize);
  BN_bin2bn(sigma_char, bigNumSize, newProof->sigma);
  offset += bigNumSize;
  
  delete [] sigma_char;
  for(int i = 0;i < cNewParams.num_sectors; ++i){
		
		int newNum;
    memcpy(&newNum,pfrom+offset,sizeof(int));
    offset += sizeof(int);

    unsigned char* mu_char = new unsigned char[newNum];
    memcpy( mu_char,pfrom + offset, newNum);
    BN_bin2bn(mu_char, newNum, newProof->mu[i]);
    offset += newNum;
    delete [] mu_char;
  }
  return newProof;
  
}

int cpor_verify_proof(CPOR_global *global, CPOR_proof *proof, CPOR_challenge *challenge, unsigned char *k_prf, BIGNUM **alpha){

	BN_CTX * ctx = NULL;
	BIGNUM *prf_i = NULL;
	BIGNUM *product = NULL;
	BIGNUM *sigma = NULL;
	int i = 0, j = 0, ret = -1;

	if(!global || !proof || !challenge || !k_prf || !alpha) return -1;

	if( ((ctx = BN_CTX_new()) == NULL)) goto cleanup;
	if( ((product = BN_new()) == NULL)) goto cleanup;
	if( ((sigma = BN_new()) == NULL)) goto cleanup;
		
	/* Compute the summation of all the products (nu_i * PRF_k(i)) */
	for(i = 0; i < challenge->l; i++){
		/* compute PRF_k(i) */
		if( ((prf_i = generate_prf_i(k_prf, challenge->I[i])) == NULL)) goto cleanup;

		/* Multiply prf_i by nu_i */
		if(!BN_mod_mul(product, challenge->nu[i], prf_i, global->Zp, ctx)) goto cleanup;
		
		/* Sum the results */
		if(!BN_mod_add(sigma, sigma, product, global->Zp, ctx)) goto cleanup;
		
		if(prf_i) BN_clear_free(prf_i);
	}
	
	/* Compute the summation of all the products (alpha_j * mu_j) */
	for(j = 0; j < cNewParams.num_sectors; j++){
		
		/* Multiply alpha_j by mu_j */
		if(!BN_mod_mul(product, alpha[j], proof->mu[j], global->Zp, ctx)) goto cleanup;	
		
		/* Sum the results */
		if(!BN_mod_add(sigma, sigma, product, global->Zp, ctx)) goto cleanup;
	}

	if(BN_ucmp(sigma, proof->sigma) == 0) ret = 1;
	else ret = 0;
	

	if(product) BN_clear_free(product);
	if(sigma) BN_clear_free(sigma);
	if(ctx) BN_CTX_free(ctx);
		
	return ret;
	
cleanup:
	if(prf_i) BN_clear_free(prf_i);
	if(product) BN_clear_free(product);
	if(sigma) BN_clear_free(sigma);
	if(ctx) BN_CTX_free(ctx);
		
	return -1;

}


int cpor_verify_file(std::string hash, CPOR_challenge *challenge, CPOR_proof *proof, CPOR_key* key){
  
	CPOR_t *t = NULL;
	FILE *tfile = NULL;
	int ret = -1;

	/* Open the t file for reading */
  fs::path tfilepath = GetDataDir() / "cpor" / "Tfiles" / hash.append(".t");
	tfile = fsbridge::fopen(tfilepath, "r");
	if(!tfile){
		LogPrintf("Fail to open tfile");
		return 0;
	}
	
	/* Get the CPOR keys */

	if(!key) return 0;
	
	/* Get t */
	// t = read_cpor_t(tfile, key);
	std::vector<unsigned char> t_bin = readFileToUnsignedChar(tfilepath.string());
	t = UnserializeT(t_bin);
	if(!t) return 0;
	
	ret = cpor_verify_proof(challenge->global, proof, challenge, t->k_prf, t->alpha);

	if(t) destroy_cpor_t(t);
  if(challenge) destroy_cpor_challenge(challenge);
  if(proof) destroy_cpor_proof(proof);
	fclose(tfile);
	
	return ret;
}

std::vector<unsigned char> SerializeT(CPOR_t* t) {
  unsigned int size = sizeof(unsigned int) + cNewParams.prf_key_size;
  for(int i =0;i<cNewParams.num_sectors;++i){
    size += BN_num_bytes(t->alpha[i]) + sizeof(int);
  }

  char* result = new char[size+1];
  unsigned int offset = 0;
  // std::cout << "SerializeT..." <<std::endl;

	memcpy(result, &t->n, sizeof(unsigned int));
	offset += sizeof(unsigned int);

  memcpy(result + offset, t->k_prf,cNewParams.prf_key_size);
  offset += cNewParams.prf_key_size;

  for(int i =0;i<cNewParams.num_sectors;++i){

		int nSize = BN_num_bytes(t->alpha[i]);
    memcpy(result + offset, &nSize,sizeof(int));
    offset += sizeof(int);

    unsigned char* alpha_char = new unsigned char[nSize];
    BN_bn2bin(t->alpha[i], alpha_char);
    memcpy(result + offset, alpha_char,nSize);
    offset += nSize;
    delete(alpha_char);
  }
  std::vector<unsigned char> vResult(result, result + size);
  delete [] result;
  return vResult;
  
}

CPOR_t* UnserializeT(std::vector<unsigned char> from) {
	unsigned char* pfrom = &from[0];
	unsigned int offset = 0;
	
	CPOR_t* t = allocate_cpor_t();
  
  // std::cout << "UnserializeT..." <<std::endl;

	memcpy(&t->n, pfrom, sizeof(unsigned int));
	offset += sizeof(unsigned int);

  memcpy(t->k_prf, pfrom + offset ,cNewParams.prf_key_size);
  offset += cNewParams.prf_key_size;

  for(int i =0;i<cNewParams.num_sectors;++i){

		int nSize;
    memcpy(&nSize, pfrom + offset, sizeof(int));
    offset += sizeof(int);

    unsigned char* alpha_char = new unsigned char[nSize];
    memcpy(alpha_char, pfrom + offset, nSize);
		BN_bin2bn(alpha_char, nSize, t->alpha[i]);
    offset += nSize;
    delete [] alpha_char;
  }
  return t;
  
}

// void destroy_cpor_key(CPOR_key *key){

// 	if(!key) return;
// 	if(key->k_enc) sfree(key->k_enc, cNewParams.enc_key_size);
// 	key->k_enc_size = 0;
// 	if(key->k_mac) sfree(key->k_mac, cNewParams.mac_key_size);
// 	key->k_mac_size = 0;
// 	if(key->global) destroy_cpor_global(key->global);
// 	sfree(key, sizeof(CPOR_key));

// 	return;
// }