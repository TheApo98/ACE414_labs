#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
size_t encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);



/* TODO Declare your function prototypes here... */
void handleErrors(void);
int readFromFile(char * filename, unsigned char * data, int * data_len);
int writeToFile(char * filename, unsigned char * data, int data_len);
unsigned char * byteAppend(unsigned char* dst, unsigned char* src, int dst_len, int src_len);

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_2 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_2 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void keygen(unsigned char *password, unsigned char *key, unsigned char *iv, int bit_mode)
{	
	// No salt is used
	const unsigned char *salt = NULL;
	// Declare cipher
	const EVP_CIPHER *cipher;
	// Set the hash function to sha1
	const EVP_MD *hash = EVP_sha1();

	// Bit mode 128 or 256
	if(bit_mode == 128) 
		cipher = EVP_aes_128_ecb();
	else
		cipher = EVP_aes_256_ecb();

	// Generate the key using the above
	if (EVP_BytesToKey(cipher, hash, salt, (unsigned char *)password, strlen((char *)password), 1, key, iv) == 0)
		handleErrors();

}


/*
 * Encrypts the data
 */
size_t encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{
	// Declare context
	EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    // Initialize the context 
    if(!(ctx = EVP_CIPHER_CTX_new())){
        handleErrors();
	}
	
	// Bit mode 128 or 256
	const EVP_CIPHER *cipher;
	if(bit_mode == 128) 
		cipher = EVP_aes_128_ecb();
	else
		cipher = EVP_aes_256_ecb();

	// Intialize the encryption
    if(EVP_EncryptInit_ex(ctx, cipher, NULL, key, iv) != 1)
        handleErrors();

	// Add the data to be encrypted
    if(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        handleErrors();
	// Set the cipher Text length
    ciphertext_len = len;

	// Finalize the encryption, append data to the cipherText
    if(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        handleErrors();
	// Update the cipher Text length
    ciphertext_len += len;

	// Free the context
    EVP_CIPHER_CTX_free(ctx);

	return (size_t)ciphertext_len;
}


/*
 * Decrypts the data and returns the plaintext size
 */
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
	// Declare context
    EVP_CIPHER_CTX *ctx;

    int len;
    int plaintext_len;

    // Initialize the context 
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

	// Bit mode 128 or 256
    const EVP_CIPHER *cipher;
	if(bit_mode == 128) 
		cipher = EVP_aes_128_ecb();
	else
		cipher = EVP_aes_256_ecb();

	// Intialize the decryption
    if(EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) != 1)
        handleErrors();

	// Add the data to be decrypted
    if(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) != 1)
        handleErrors();
	// Set the plain Text length
    plaintext_len = len;

	// Finalize the decryption, append data to the plainText
    if(EVP_DecryptFinal_ex(ctx, plaintext + len, &len) != 1)
        handleErrors();
	// Update the plain Text length
    plaintext_len += len;

	// Free the context
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}


/*
 * Generates a CMAC
 */
void gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{
    size_t cmac_len = 0;	// not used anymore
	// Declare CMAC context
    CMAC_CTX *ctx;

    // Initialize the context 
    if(!(ctx = CMAC_CTX_new()))
        handleErrors();

	// Bit mode 128 or 256
    const EVP_CIPHER *cipher;
	if(bit_mode == 128) 
		cipher = EVP_aes_128_ecb();
	else
		cipher = EVP_aes_256_ecb();

	// Intialize the CMAC generation
    if(CMAC_Init(ctx, key, (size_t)bit_mode/8, cipher, NULL) != 1)
        handleErrors();

	// Add the data to the process
    if(CMAC_Update(ctx, data, data_len) != 1)
        handleErrors();

	// Finalize the CMAC generation
    if(CMAC_Final(ctx, cmac, &cmac_len) != 1)
        handleErrors();

	// Free the context
    CMAC_CTX_free(ctx);

    // return cmac_len;
}


/*
 * Verifies a CMAC
 */
int verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	// If either is null, return
	if(cmac1 == NULL || cmac2 == NULL)
        return 0;
    // Compare the 2 'strings'
    return(memcmp(cmac1, cmac2, BLOCK_SIZE) == 0);
}



/* TODO Develop your functions here... */
void handleErrors(void){
	fprintf(stderr, "Error!! Exiting...\n");
	exit(EXIT_FAILURE);
}

int readFromFile(char * filename, unsigned char * data, int * data_len){
    FILE *fp;
   	fp = fopen(filename, "rb");
    if(fp == NULL){
        return 1;
    }
    /* File commands */ 
    /* (necessary for reading special characters like EOF, etc) */
    fseek(fp, 0, SEEK_END);     // go to file end
    *data_len = ftell(fp);           // calculate the file size
    rewind(fp);                 // go to file start and...
    if(fread(data, *data_len, sizeof(unsigned char), fp) == 0){
        fclose(fp);
        return 1;
    }
    fclose(fp);
    return 0;
}

int writeToFile(char * filename, unsigned char * data, int data_len){
    FILE *fp;
   	fp = fopen(filename, "wb");
    if(fp == NULL){
        return 1;
    }

    if(fwrite(data , sizeof(unsigned char) , data_len , fp ) == 0){
		fclose(fp);
        return 1;
	}
    fclose(fp);
    return 0;
}

/**
 * @brief Appends source bytes to destination bytes
 * 
 * @param dst Destination bytes
 * @param src Source bytes
 * @param dst_len Destination buffer size
 * @param src_len Source buffer size
 * @return unsigned char* The buffer with the concatenated bytes
 */
unsigned char * byteAppend(unsigned char* dst, unsigned char* src, int dst_len, int src_len){
    unsigned char * buff = dst;
    for(int i=0; i<src_len; i++){
        buff[dst_len+i] = src[i];
    }
    return buff;
}

/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 0 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 2 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 3 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);



	/* TODO Develop the logic of your tool here... */

	// Initialize variables 
	int 	plain_len 		= 256;      // random length
	int 	cipher_cmac_len	= 0;
	size_t 	cipher_len 		= 0;
	size_t 	cmac_len 		= BLOCK_SIZE;      
	unsigned char * iv = NULL;
	// unsigned char * iv 			= (unsigned char *)malloc(sizeof(char)*bit_mode/8);
	unsigned char * key			= (unsigned char *)malloc(sizeof(char)*bit_mode/8); 
	unsigned char * plainText 	= (unsigned char *)malloc(sizeof(unsigned char)*plain_len);
	unsigned char * cipherText 	= (unsigned char *)malloc(sizeof(unsigned char)*plain_len);
	unsigned char * cmac 		= (unsigned char *)malloc(sizeof(unsigned char)*plain_len);
	unsigned char * cmac_gen	= (unsigned char *)malloc(sizeof(unsigned char)*plain_len);
	unsigned char * cipher_cmac = (unsigned char *)malloc(sizeof(unsigned char)*plain_len);
	
	switch (op_mode)
	{
	case 0:						/* Encryption */	
		// Generate key
		keygen(password, key, iv, bit_mode);

		// Read plain text from file
		if(readFromFile(input_file, plainText, &plain_len) == 1){
			fprintf(stderr, "Failed to read from file\n");
			exit(EXIT_FAILURE);
		}
		// Encryption
		cipher_len = encrypt(plainText, (size_t)plain_len, key, iv, cipherText, bit_mode);
		// Reallocation to aviod memory leaks 
		cipherText 	= (unsigned char*)realloc(cipherText, sizeof(unsigned char)*cipher_len);
		plainText 	= (unsigned char*)realloc(plainText, sizeof(unsigned char)*plain_len);

		/* Print password, key */ 
		printf("Pass: %s\n", password);
		printf("Key: ");
		print_hex(key, sizeof(char)*bit_mode/8);
		
		/* Print plain and cipher Text */
		printf("\tPlain text length: %d\n", plain_len);
		print_string(plainText, (size_t)plain_len);
		printf("\tCipher text length: %d\n", (int)cipher_len);
		print_hex(cipherText, cipher_len);

		// Write cipher text to file
		if(writeToFile(output_file, cipherText, cipher_len) == 1){
			fprintf(stderr, "Failed to write to file\n");
			exit(EXIT_FAILURE);
		}

		break;

	case 1:						/* Decryption */
		// Generate key
		keygen(password, key, iv, bit_mode);

		// Read cipher from file
		if(readFromFile(input_file, cipherText, (int*)&cipher_len) == 1){
			fprintf(stderr, "Failed to read from file\n");
			exit(EXIT_FAILURE);
		}
		// Decryption
		int plain_len = decrypt(cipherText, cipher_len, key, iv, plainText, bit_mode);
		
		// Reallocation to aviod memory leaks 
		cipherText 	= (unsigned char*)realloc(cipherText, sizeof(unsigned char)*cipher_len);
		plainText 	= (unsigned char*)realloc(plainText, sizeof(unsigned char)*plain_len);
		
		/* Print password, key */ 
		printf("Pass: %s\n", password);
		printf("Key: ");
		print_hex(key, sizeof(char)*bit_mode/8);

		/* Print plain and cipher Text */
		printf("\tCipher text length: %d\n", (int)cipher_len);
		print_hex(cipherText, cipher_len);
		printf("\tPlain text length: %d\n", plain_len);
		print_string(plainText, (size_t)plain_len);

		// Write plain text to file
		if(writeToFile(output_file, plainText, plain_len) == 1){
			fprintf(stderr, "Failed to write to file\n");
			exit(EXIT_FAILURE);
		}

		break;

	case 2:			/* Signing and Encryption */
		// Generate key
		keygen(password, key, iv, bit_mode);

		// Read plain text from file
		if(readFromFile(input_file, plainText, &plain_len) == 1){
			fprintf(stderr, "Failed to read from file\n");
			exit(EXIT_FAILURE);
		}
		// Encrypt
		cipher_len = encrypt(plainText, (size_t)plain_len, key, iv, cipherText, bit_mode);
		// Reallocation to aviod memory leaks 
		plainText = (unsigned char*)realloc(plainText, sizeof(unsigned char)*plain_len);
		cipherText = (unsigned char*)realloc(cipherText, sizeof(unsigned char)*cipher_len);

		/* Print password, key */
		printf("Pass: %s\n", password);
		printf("Key: ");
		print_hex(key, sizeof(char)*bit_mode/8);	

		/* Print plain and cipher Text */
		printf("\tPlain text length: %d\n", plain_len);
		print_string(plainText, (size_t)plain_len);
		printf("\tCipher text length: %d\n", (int)cipher_len);
		print_hex(cipherText, cipher_len);

		// Generate the cmac
		gen_cmac(plainText, (size_t)plain_len, key, cmac, bit_mode);
		// Concatenate cipherText and cmac
		unsigned char * buff = byteAppend(cipherText, cmac, cipher_len, cmac_len);
		cipher_cmac_len = cipher_len + cmac_len;

		/* Print cmac */ 
		printf("\tCMAC with length: %d\n", (int)cmac_len);
		print_hex(cmac, cmac_len);    
		/* Print concatenated string */
		printf("\tConcatenated string with length: %d\n", cipher_cmac_len);
		print_hex(buff, cipher_cmac_len);

		// Write cipher and cmac to file
		if(writeToFile(output_file, buff, cipher_len+cmac_len) == 1){
			fprintf(stderr, "Failed to write in file\n");
			exit(EXIT_FAILURE);
		}

		break;
	case 3:			/* Verification and decryption */
		// Generate key
		keygen(password, key, iv, bit_mode);

		// Read cipher from file
		int cipher_cmac_len = 0;
		if(readFromFile(input_file, cipher_cmac, &cipher_cmac_len) == 1){
			fprintf(stderr, "Failed to read from file\n");
			exit(EXIT_FAILURE);
		}
		cipher_len = cipher_cmac_len - cmac_len;

		// Extract cipherText from concatenated "string"
		memcpy(cipherText, cipher_cmac, cipher_len); 
		// Extract CMAC from concatenated "string"
		cmac = byteAppend(cipher_cmac+cipher_len, cipher_cmac+cipher_len, 0, cmac_len);
		// memcpy(cmac1, cipher_cmac+cipher_len, bit_mode/8);   
		// cipherText = byteAppend(cipher_cmac+cmac_len, cipher_cmac+cmac_len, 0, cipher_len);
		// cmac = byteAppend(cipher_cmac, cipher_cmac, 0, cmac_len);

		/* Print password, key */
		printf("Pass: %s\n", password);
		printf("Key: ");
		print_hex(key, sizeof(char)*bit_mode/8);

		/* Print cmac from file */ 
		printf("\tCMAC(file) with length: %d\n", (int)cmac_len);
		print_hex(cmac, cmac_len);  
		/* Print plain and cipher Text */
		printf("\tCipher text length: %d\n", (int)cipher_len);
		print_hex(cipherText, cipher_len);
		
		// Decrypt cipherText
		plain_len = decrypt(cipherText, cipher_len, key, iv, plainText, bit_mode);

		printf("\tPlain text length: %d\n", plain_len);
		print_string(plainText, (size_t)plain_len);
		
		// Generate CMAC for verification
		gen_cmac(plainText, (size_t)plain_len, key, cmac_gen, bit_mode);

		/* Print cmac from generator */ 
		printf("\tCMAC(Gen) with length: %d\n", (int)cmac_len);
		print_hex(cmac_gen, cmac_len); 

		// Check for verification
		if(verify_cmac(cmac, cmac_gen) == 1)
			printf("\tVerification successful!!!\n");
		else
			printf("\tVerification failed!!!\n");
		
		break;
		
	default:
		break;
	}


	/* Initialize the library */


	/* Keygen from password */


	/* Operate on the data according to the mode */
	/* encrypt */

	/* decrypt */

	/* sign */

	/* verify */
		

	/* Clean up */
	free(key);
	// free(iv);
	free(plainText);
	free(cipherText);
	// free(cmac);
	free(cmac_gen);
	free(cipher_cmac);

	free(input_file);
	free(output_file);
	free(password);


	/* END */
	return 0;
}


/*
Commands (Task F):
1) ./assign_2 -i ../files/encryptme_256.txt -o ../files/decryptme_256.txt -p TUC2017030142 -b 256 -e
2) ./assign_2 -i ../files/hpy414_decryptme_128.txt -o ../files/hpy414_encryptme_128.txt -p hpy414 -b 128 -d
3) ./assign_2 -i ../files/signme_128.txt -o ../files/verifyme_128.txt -p TUC2017030142 -b 128 -s
4.1) ./assign_2 -i ../files/hpy414_verifyme_128.txt -o fakefilename -p hpy414 -b 128 -v
4.2) ./assign_2 -i ../files/hpy414_verifyme_256.txt -o fakefilename -p hpy414 -b 256 -v
*/