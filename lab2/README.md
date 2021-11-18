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
void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
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
1. ***Cipher:*** AES_ECB with 128 or 256 bit key length 
2. ***Hashing algorithm:*** SHA1 in our case
3. ***Salt:*** a plain text to be added to the hash function with the data (Optional in our case)
4. ***Password:*** the data to be hashed, specified by the user
5. ***Count*** the iteration count ('1' in our case)
6. ***Key pointer:*** to store the generated key
7. ***IV pointer:*** to store the generated IV (NULL in our case)

The function returns an error through ```handleErrors()``` function if there is a problem with the key generation. 

## <center>*Data Encryption*</center>


<p>&nbsp;</p>

## <center>*Main Function*</center>
The cases '0' and '1' are straight forward and the comments in source file are sufficient, so we won't get in to much detail


## License
<p style="color:red;">Apostolos Gioumertakis</p>