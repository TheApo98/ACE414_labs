# Simple_crypto

Simple_crypto is a cryptographic library, in which, three basic but fundamental cryptographic algorithms are implemented.  (i) One-time pad, (ii) Caesar’s cipher and (iii) Vigenère’s cipher.

## Compilation

To compile the code, use the following command:

```bash
make
```

## Functions
### <center style="color:white;">*Random character generator*</center>

```c
#define MAX 127                         // max usable character
#define MIN 32                          // min usable character
#define URANDOM_DEVICE "/dev/urandom"
char random_char() {
    int c;
    do {
        c = fgetc(urandom);
        if (c == EOF) {
            fprintf(stderr, "Failed to read from %s\n", URANDOM_DEVICE);
            exit(EXIT_FAILURE);
        }
    }
    while (c > MAX || c < MIN);
    return (char) c;
}
```
This function returns a random character every time it's called, using the "/dev/urandom" file. The character must be between the MIN and MAX values of the ASCII table and this is accomplished with a ```do{} while()``` loop until we get the desired character.


<!-- One-time pad -->
### <center style="color:white;">*One-time pad cipher*</center>
```c
// One-time pad
char * one_time_pad_ENCR(char * msg){
    randomKEY = (char *) malloc(strlen(msg)+1);
    char * outputWord = (char *) malloc(strlen(msg)+1); 
    for(int i=0; i<strlen(msg)+1; i++){
        *(randomKEY + i) = random_char(); 
        *(outputWord + i) = (char) (*(randomKEY + i) ^ *(msg + i));
    }
    return outputWord;
}
```

>This function encrypts a string that is given as an input (argument). A pseudo random key is generated using the ```random_char()``` function. With the help of a ```for``` loop, each character of the pseudorandom key is generated and then **XOR-ed** with the current character of the plain text (msg). The characters are then stored in a string , which is returned at the end. The pseudorandom key is stored as a global variable for further use (decryption).


```c
char * one_time_pad_DECR(char * encrMsg){
    char * outputWord = (char *) malloc(strlen(encrMsg)+1); 
    for(int i=0; i<strlen(encrMsg)+1; i++){
        *(outputWord + i) = (char) (*(randomKEY + i) ^ *(encrMsg + i));
    }
    return outputWord;
}
```

>This is complementary to the ```one_time_pad_ENCR(char * msg)``` function. It decrypts a string that is given as an input (argument). Using the pseudorandom key previously generated, with the help of a ```for``` loop, each character of the key is **XOR-ed** with each character of the ciphered text (encMsg). The characters are then stored in a string , which is returned at the end. 

#### <center style="color:white;">*Observations*</center>
>The ciphered text doesn't always contain printable characters. This is because the result of the XOR between two characters may exceed the limits of the printable characters of the ASCII table. Be that as it may, the ciphered text can be successfully deciphered.


<!-- Ceasar's cipher -->
### <center style="color:white;">*Ceasar's cipher*</center>

```c
#define ALPHABET_SIZE 26
#define NUM_SIZE 10

// Ceasar's cipher
char * ceasars_cipher_ENCR(char * msg, int key){
    char * cipherText = (char *) malloc(strlen(msg)); 
    int charVal = 0;
    for(int i=0; i<strlen(msg); i++){
        charVal = (int)msg[i];
        if(msg[i] >= 'A' && msg[i]<='Z'){
            charVal = charVal - 'A';
            *(cipherText + i) = ((charVal + key) % ALPHABET_SIZE) + 'A';
        }
        else if(msg[i] >= 'a' && msg[i]<='z'){
            charVal = charVal - 'a';
            *(cipherText + i) = ((charVal + key) % ALPHABET_SIZE) + 'a';
        }
        else if(isdigit(msg[i]) != 0){
            charVal = charVal - '0';
            *(cipherText + i) = ((charVal + key) % NUM_SIZE) + '0';
        }
        else
            *(cipherText + i) = *(msg + i);
    }
    return cipherText;
}
```
This function requires two(2) arguments, the plain text (msg) and an integer, the key. Again, with the help of a ```for``` loop, each character of the plain text is shifted properly, according to the value of the key. We have four(4) different cases:

1. ***Character is Uppercase letter (A-Z)***
   
   >First we clear the ASCII table offset to get a character value 0-25 (Range of the English alphabet): 
   ```c
   charVal = charVal - 'A';
   ```
   >The decimal value of the key and the current character of the plaintext are added and then we get the remainder of the division (modulo operator) with the number '26' (Length of the English alphabet), to achieve a cyclic shift among the letters of the Alphabet. Finally, we restore the ASCII table offset by adding the result with the character 'A', to get the ciphered character.  
   ```c
   *(cipherText + i) = ((charVal + key) % ALPHABET_SIZE) + 'A';
   ```  
2. ***Character is Lowercase letter (a-z)***
   
   >Same as the first case but we subtract and add with the character 'a'. 
3. ***Character is a number (0-9)***
   
   >Same as the first case but we subtract and add with the character '0'. Also the remainder of the division happens with the nuber '10' (Size of the decimal number set). 
4. ***Character is a special character (\*,@,!)***
   
   >This case is used to skip special characters from the encryption process. They are just copied to the ciphered text string. 


```c
char * ceasars_cipher_DECR(char * encMsg, int key){
    char * plainText = (char *) malloc(strlen(encMsg)); 
    int charVal = 0;
    for(int i=0; i<strlen(encMsg); i++){
        charVal = (int)encMsg[i];
        if(encMsg[i] >= 'A' && encMsg[i] <= 'Z'){
            charVal = charVal - 'A';
            *(plainText + i) = abs((abs(charVal - key) % ALPHABET_SIZE) - ALPHABET_SIZE) + 'A';
        }
        else if(encMsg[i] >= 'a' && encMsg[i] <= 'z'){
            charVal = charVal - 'a';
            *(plainText + i) = abs((abs(charVal - key) % ALPHABET_SIZE) - ALPHABET_SIZE) + 'a';
        }
        else if(isdigit(encMsg[i]) != 0){
            charVal = charVal - '0';
            *(plainText + i) = abs((abs(charVal - key) % NUM_SIZE) - NUM_SIZE) + '0';
        }
        else
            *(plainText + i) = *(encMsg + i);
    }
    return plainText;
}
```
This function is complementary to ```ceasars_cipher_ENCR(char * msg, int key)```. It also requires two(2) arguments, the ciphered text (encMsg) and an integer, the key. Again, with the help of a ```for``` loop, each character of the ciphered text is shifted back properly, according to the value of the key, to decrypt the input string. We have four(4) different cases:

1. ***Character is Uppercase letter (A-Z)***
   
   >First, in the same way as before, we clear the ASCII table offset to get a character value 0-25 (Range of the English alphabet): 
   ```c
   charVal = charVal - 'A';
   ```
   >The decimal value of the key and the current character of the ciphered text are subtracted and then we get the remainder of the division (modulo operator) with the number '26' (Length of the English alphabet), to achieve a cyclic shift among the letters of the Alphabet. The result is the complement of the value of the plain text character we are trying to decipher. So, to get the value, we subtract with the the number '26' (Length of the English alphabet). Finally, we restore the ASCII table offset by adding the result with the character 'A', to get the plain text character: 
   ```c
   *(plainText + i) = abs((abs(charVal - key) % ALPHABET_SIZE) - ALPHABET_SIZE) + 'A';
   ```  
2. ***Character is Lowercase letter (a-z)***
   
   >Same as the first case but we subtract and add with the character 'a'. 
3. ***Character is a number (0-9)***
   
   >Same as the first case but we subtract and add with the character '0'. Also the remainder of the division happens with the nuber '10' (Size of the decimal number set) and the subtraction of the complement. 
4. ***Character is a special character (\*,@,!)***
   
   >Once again, this case is used to skip special characters from the decryption process. They are just copied to the plain text string. 




## License
<p style="color:red;">Apostolos Gioumertakis</p>