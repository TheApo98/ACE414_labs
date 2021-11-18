# Assignment_2

In this assignment you are going to develop a symmetric encryption tool in C, using the OpenSSL toolkit https://www.openssl.org/. The purpose of this assignment is to provide you the opportunity to get familiar with the very popular general-purpose cryptography toolkit and acquire hands-on experience in implementing simple cryptographic applications. The tool will provide encryption, decryption, CMAC signing and CMAC verification functionality.

## Compilation

To compile the code, use the following command:

```bash
make
```

## GCC version
To get the version of the gcc compiler, run:
```bash
# Command 
    gcc --version

# Result
    gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
```

## Usage
Help menu of the tool:
```
./assign_2 -h
./assign_2: option requires an argument -- 'h'

Usage:
    assign_2 -i in_file -o out_file -p passwd -b bits [-d | -e | -s | -v]
    assign_2 -h

Options:
 -i    path    Path to input file
 -o    path    Path to output file
 -p    psswd   Password for key generation
 -b    bits    Bit mode (128 or 256 only)
 -d            Decrypt input and store results to output
 -e            Encrypt input and store results to output
 -s            Encrypt+sign input and store results to output
 -v            Decrypt+verify input and store results to output
 -h            This help message
```

<p>&nbsp;</p>

## Utility Functions
We needed to construct some helper functions for reading from files, writing to files, concatenating byte buffers and handling errors.

## <center>*Error Handler*</center>
```c
void handleErrors(void){
	fprintf(stderr, "Error!! Exiting...\n");
	exit(EXIT_FAILURE);
}
```

## <center>*Read from file*</center>
```c
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
```
>This function is used to read bytes from a file. It is used both for the plain and cipher text. It takes as input three(3) arguments, the filename, a pointer to store the data and a pointer  for the length of the data (call by reference).<br>
This function seeks for the end of the file to calculate the size of the data it contains and then using ```fread()```  function, reads the entire file (using the data_len as input) and store the data into a buffer.<br>
If an error is encountered, returns 1 or if the read is successful, returns 0;
## <center>*Write to file*</center>
```c
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
```
>This function is used to writes bytes to a file. It is used both for the plain and cipher text.<br>
It takes as input three(3) arguments, the filename, a pointer to the data and a integer for the length of the data.<br> 
This function writes a specific number of bytes specified by data_len variable, from the data pointed by the pointer, to the file using the ```fwrite()```  function.
If an error is encountered, returns '1' or if the write is successful, returns '0';

## <center>*Concatenate*</center>
```c
unsigned char * byteAppend(unsigned char* dst, unsigned char* src, int dst_len, int src_len){
    unsigned char * buff = dst;
    for(int i=0; i<src_len; i++){
        buff[dst_len+i] = src[i];
    }
    return buff;
}
```
>This function takes as input the destination and source byte buffers and their lengths. It returns as output a buffer with the concatenated byte, meaning the source data appended to the destination data. <br>
It works by initializing the buffer to the same address in the memory as the destination. Then using a loop, the source data get appended with an offset equal to the dst_len, by coping each byte to the buffer until src_len is reached. <br> 
The function can also be used for unconcatenating data. 

<p>&nbsp;</p>

## Main Functions
These functions provide the main functionality of the tool for encrypting, decrypting, signing and verifying data.

## <center>*Key Derivation Function (KDF)*</center>
```c
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
```
This function is used to generate a key and an Initialization Vector(IV), using the AES_ECB from the EVP API. In our case, the IV is not needed.<br> 
By default, for generating a key and IV with input data with the ```EVP_BytesToKey()``` function, some things are required:
1. ***Cipher:*** AES_ECB mode with 128 or 256 bit key length 
2. ***Hashing algorithm:*** SHA1 in our case
3. ***Salt:*** a plain text to be added to the hash function with the data (Optional in our case)
4. ***Password:*** the data to be hashed, specified by the user
5. ***Count*** the iteration count ('1' in our case)
6. ***Key pointer:*** to store the generated key
7. ***IV pointer:*** to store the generated IV (NULL in our case)

The function returns an error through ```handleErrors()``` function if there is a problem with the key generation. 

## <center>*Data Encryption*</center>
```c
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
```
This function is used to encrypt the plain text data with a key and IV that are given as an input. There are multiple stages for the encryption process:
1. ***Context initialization:***<br>
    A new cipher contex object is created 
2. ***Cipher mode:***<br>
    Depending on the caller input, AES_ECB mode with 128 or 256 bit key length is selected
3. ***Encryption process initialization:***
    The encryption starts with the cipher context, cipher mode, implementation, key and IV as an input. Implementation is set to "NULL".
4. ***Encryption process update:***
    The encryption is updated with the plain text information and the cipherText pointer for storing the encrypted data. Again the cipher context is necessary as input
5. ***Encryption process finalization:***
    The encryption is finalized and more encrypted data are appended to the previously created cipher text. The length of the new data is returned (call by reference). Again the cipher context is necessary as input
6. ***Context clean up:***<br>
    The cipher context is freed and the encryption ends

Every stage of the encryption process is checked for error. If an error occurs, is handled by ```handleErrors()```.<br>
The function returns the length of the ciphered data, useful value for printing and writing the data to files without any problems.


## <center>*Data Decryption*</center>
```c
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
```
This function is used to decrypt the cipher text data with a key and IV that are given as an input. There are multiple stages for the decryption process:
1. ***Context initialization:***<br>
    A new cipher contex object is created 
2. ***Cipher mode:***<br>
    Depending on the caller input, AES_ECB mode with 128 or 256 bit key length is selected
3. ***Decryption process initialization:***
    The decryption starts with the cipher context, cipher mode, implementation, key and IV as an input. Implementation is set to "NULL".
4. ***Decryption process update:***
    The decryption is updated with the cipher text information and the plainText pointer for storing the data. Again the cipher context is necessary as input
5. ***Decryption process finalization:***
    The decryption is finalized and more plain text data are appended to the previously created plain text. The length of the new data is returned (call by reference). Again the cipher context is necessary as input
6. ***Context clean up:***<br>
    The cipher context is freed and the decryption ends

Every stage of the decryption process is checked for errors. If an error occurs, is handled by ```handleErrors()```.<br>
The function returns the length of the plain text data, useful value for printing and writing the data to files without any problems.


## <center>*Data Signing (CMAC)*</center>
```c
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
```
This function is used to sign the data to be encrypted by generating a 16-byte CMAC. There are multiple stages for the signing process:
1. ***Context initialization:***<br>
    A new cmac contex object is created 
2. ***Cipher mode:***<br>
    Depending on the caller input, AES_ECB mode with 128 or 256 bit key length is selected
3. ***Signing process initialization:***
    The signing starts with the cipher context, key, key length, cipher mode and implementation as an input. Implementation is set to "NULL".
4. ***Signing process update:***
    The signing is updated with the plain text information required for the CMAC generation. Again the cipher context is necessary as input
5. ***Signing process finalization:***
    The decryption is finalized, the length of CMAC is stored (in bytes), which equals the cipher block size. Unless cmac_len is NULL, it encrypts the last block, padding it if required and stores the CMAC data to the cmac pointer. Again the cipher context is necessary as input
6. ***Context clean up:***<br>
    The cipher context is freed and the decryption ends

Every stage of the signing process is checked for errors. If an error occurs, is handled by ```handleErrors()```.<br>
The function returns the length of the plain text data, useful value for printing and writing the data to files without any problems.

## <center>*Data Verification (CMAC)*</center>
```c
int verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{
	if(cmac1 == NULL || cmac2 == NULL)
        return 0;
        
    return(memcmp(cmac1, cmac2, BLOCK_SIZE) == 0);
}
```
This function verifies the encrypted data by comparing the CMAC that came with the cipher text and the CMAC that is generated from the decryption process (plain text)

<p>&nbsp;</p>

## <center>*Main Function*</center>
The cases '0' and '1' are straight forward and the comments in source file are sufficient, so we won't get in to much detail

<p>&nbsp;</p>

## Task F.4
Verify the files “hpy414_verifyme_256.txt” and “hpy414_verifyme_128.txt” using the appropriate key size, as the filename specifies. The keys should be derived by the password “hpy414”.<br>
The output is stated below:
## <center>*Verifying with 128-bits*</center>
```bash
# command
./assign_2 -i ../files/hpy414_verifyme_128.txt -o fakefilename -p hpy414 -b 128 -v

# output
Pass: hpy414
Key: 8D 3B 78 B5 73 3F 18 9D 72 1A A1 52 48 6A B7 EE 
        CMAC(file) with length: 16
A6 18 94 13 55 F2 6B D4 77 C0 CF AF C3 B7 CD A1 
        Cipher text length: 80
A7 22 4B B8 66 17 E2 A2 06 EA 33 E3 34 7E 94 1C 
E8 16 8F B5 E9 71 50 8A 88 7B E0 B1 0D 13 3C 95 
6C D2 A3 82 BA FA B9 2D 46 E0 31 48 76 F1 2B 0C 
D5 C6 32 45 BF A8 44 24 D0 77 A9 BE 55 B2 59 B9 
B1 38 90 C7 D4 18 B0 4D 39 B7 97 E8 D6 6A 46 00 
        Plain text length: 66
Hello HPY414

This file can be verified with a 128-bit key.

BB! 

        CMAC(Gen) with length: 16
66 4C 57 6F 54 4B DC 7B 8E 10 FC F2 E2 4C BD B5 
        Verification failed!!!
```

## <center>*Verifying with 256-bits*</center>
```bash
# command
./assign_2 -i ../files/hpy414_verifyme_256.txt -o fakefilename -p hpy414 -b 256 -v

# output
Pass: hpy414
Key: 8D 3B 78 B5 73 3F 18 9D 72 1A A1 52 48 6A B7 EE 
3B 30 43 27 DE C4 42 D0 A9 BA 93 A8 4C 67 A0 68 
        CMAC(file) with length: 16
D9 69 1C A9 38 DE F4 66 D2 91 EC B5 B8 D7 79 A8 
        Cipher text length: 80
39 21 9C 76 10 EB 0A 20 04 E7 8F C5 11 DB F8 69 
EF 7D 57 F4 AA CC 66 46 1C 21 4F 50 96 5C 36 6E 
A7 9E 3E 10 6C 63 FB E9 5A 29 D6 5C 79 E9 45 37 
02 FE A8 0C 4A 0A CA 35 D3 0D 3E F7 DA 59 13 EF 
68 EE 61 91 EF 5C FD 5E C9 1D B4 37 07 ED 6C 07 
        Plain text length: 64
Hello HPY414

This file can be verified with a 256-bit key

BB!

        CMAC(Gen) with length: 16
DC 35 11 2E 76 B5 64 29 25 99 E4 ED 20 B4 9E 2B 
        Verification failed!!!
```
It is clear that the CMACs don't match so the verification process failed in both cases

<p>&nbsp;</p>


## License
<p style="color:red;">Apostolos Gioumertakis</p>