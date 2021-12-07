# Assignment_4: RSA 

### Introduction 
In this assignment you are going to develop an asymmetric encryption tool in C from scratch. The purpose of this assignment, now that you are familiar with implementing simple ciphers as well as using real encryption toolkits, is to provide you the opportunity to get familiar with the internals of a popular encryption scheme, namely RSA. The tool will provide RSA key-pair generation, encryption and decryption.
 

## Compilation

To compile the code, use the following command:

```bash
make all
```

To run the code, use the following commands:

```bash
make run
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
./assign_4 -h
./assign_4: option requires an argument -- 'h'

Usage:
    assign_4 -g 
    assign_4 -i in_file -o out_file -k key_file [-d | -e]
    assign_4 -h

Options:
 -i    path    Path to input file
 -o    path    Path to output file
 -k    path    Path to key file
 -d            Decrypt input and store results to output
 -e            Encrypt input and store results to output
 -g            Generates a keypair and saves to 2 files
 -h            This help message
```

<p>&nbsp;</p>

## Main Functions
These functions provide the main functionality of the tool for key generation, encryption and decryption.

## <center>*Key Derivation Function (KDF)*</center>
In this function, the RSA key-pair is generated. Using the ```sieve_of_eratosthenes(int limit, int *primes_sz)``` function , a pool of prime numbers is generate ranging from 2 to *"RSA_SIEVE_LIMIT"* defined in "util.h" library. Then two (2) pseudorandom prime numbers are selected from the pool using the ```rand()```. Because the output for ```rand()``` ranges from 0 to RAND_MAX, the remainder with the division of "primes_sz" (pool size) is kept, so that the limits of the array with the primes is not exceeded. If they prime numbers are equal, the process explained above, repeates until the are not equal (to increase randomness). The results from ```rand()``` correspond to the indices of two (2) prime numbers in the array, 'p' and 'q'. <br>
The variable 'N' is calculated by multiplying 'p' and 'q' and then Φ(n) is calculated multiplying 'p-1' and 'q-1'. Using the function ```choose_e(fi_n)```, 'e' is choosen and using the function ```mod_inverse(e, fi_n)``` 'd' is calculated. <br>
The variables 'n' and 'e' together make up the **public key** used for encrypting plain text and the variables 'n' and 'd' together make up the **private key** used for decrypting ciphered text. The keys are then store in two (2) files, "public.key" and "private.key" in the "outputFiles" directory, using the function ```writeKeyToFile()```.

<p>&nbsp;</p>

## <center>*Data Encryption*</center>
```c
void rsa_encrypt(char *input_file, char *output_file, char *key_file)
```
This function is use to encrypt data using the a **Public key**. It also works with the **Private key** as input. <br>
First, the key is read from the file using the ```readKeyFromFile(key_file, &n, &e)``` , located in the util.c file, which gets the filename as input and returns the 'n' and 'e' variables (call by reference). The 'n' and 'e' values are important to successfully encrypt data. <br>
Next, the plain text data is read using the ```readFromFile(input_file, plainText, &plain_len)``` function. This fucntion returns the data in the "plainText" variable and their length in the "plain_len" variable. <br>
Now comes the fun part, where the data are encrypted. Using a loop, each character of the plain text is encrypted with the previously obtained 'e' and 'n' values, using the ```largeNumberPowerMod(plainText[i], e, n)``` function. This function performs the mathematical equation: c = m^e mod n, with 'm' being the plain text and 'c' being the cipher text "character" . This result is stored in an array of "size_t" variables, each one being 8-bytes long (64 bit system). Because each character of the plain text is 1-byte and after the encryption becomes 8-bytes (size_t variable), the size of the array containing the cipherText must be 8 (or sizeof(size_t)) times bigger than the array containing the plain text. <br>
Finally, the cipher text is written to the output file using ```writeToFile(output_file, cipherText, cipher_len)``` function , with "cipherText" being the pointer to the encrypted data and "cipher_len" the size (in bytes) of the array.     

<p>&nbsp;</p>

## <center>*Data Encryption*</center>
```c
void rsa_decrypt(char *input_file, char *output_file, char *key_file)
```
This function is complementary to the previous one. It is use to decrypt data using the a **Private key**. It also works with the **Public key** as input. <br>
First, the key is read from the file using the ```readKeyFromFile(key_file, &n, &d)``` , located in the util.c file, which gets the filename as input and returns the 'n' and 'd' variables (call by reference). The 'n' and 'd' values are important to successfully decrypt data. <br>
Next, the cipher text data is read using the ```readFromFile(input_file, cipherText, (int*)&cipher_len``` function. This function returns the data in the "cipherText" variable and their length in the "cipher_len" variable. <br>
Now comes the fun part, where the data are decrypted. Using a loop, each character of the cipher text is decrypted with the previously obtained 'd' and 'n' values, using the ```largeNumberPowerMod(cipherText[i], d, n)``` function. This function performs the mathematical equation: m = c^d mod n, with 'c' being the cipher text and 'm' being the plain text "character" . This result is stored in an array of "unsigned char" variables, each one being 1-bytes long. Because each "character" of the cipher text is 8-byte and after the decryption becomes 1-bytes (unsigned char variable), the size of the array containing the plain text must be 8 (or sizeof(size_t)) times smaller than the array containing the cipher text. <br>
Finally, the cipher text is written to the output file using ```writeToFile(output_file, plainText, plain_len)``` function , with "plainText" being the pointer to the decrypted data and "plain_len" the size (in bytes) of the array.    


<p>&nbsp;</p>

## <center>*Using the tool*</center>
To test the tool, the fooling command where executed:
1. Encryption using the public key 
   ```
   ./assign_4 -i ../files/hpy414_encryptme_pub.txt -o ../outputFiles/TUC2017030142_encrypted_pub.txt -k ../files/hpy414_public.key -e
   ```
2. Decryption using the public key 
   ```
   ./assign_4 -i ../files/hpy414_decryptme_pub.txt -o ../outputFiles/TUC2017030142_decrypted_pub.txt -k ../files/hpy414_public.key -d
   ```

2. Encryption using the private key
   ```
   ./assign_4 -i ../files/hpy414_encryptme_priv.txt -o ../outputFiles/TUC2017030142_encrypted_priv.txt -k ../files/hpy414_private.key -e
   ```
3. Decryption using the private key
   ```
   ./assign_4 -i ../files/hpy414_decryptme_priv.txt -o ../outputFiles/TUC2017030142_decrypted_priv.txt -k ../files/hpy414_private.key -d
   ```



## License
<p style="color:red;">Apostolos Gioumertakis</p>