# Simple_crypto

Simple_crypto is a cryptographic library, in which, three basic but fundamental cryptographic algorithms are implemented.  (i) One-time pad, (ii) Caesar’s cipher and (iii) Vigenère’s cipher.

## Compilation

To compile the code, use the following command:

```bash
make
```

<p>&nbsp;</p>

## Functions
## <center style="color:white;">*Random character generator*</center>

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

<p>&nbsp;</p>

## <center style="color:white;">*Spelling checker*</center>

```c
void spelling_check(char text_lt, char  key_lt){
    if (isalpha(text_lt) == 0 || isalpha(key_lt) == 0){
        fprintf(stderr, "[Vigenere] Plain text or key is not alphabet\n");
        exit(EXIT_FAILURE);
    }
    if (isupper(text_lt) == 0 || isupper(key_lt) == 0){
        fprintf(stderr, "[Vigenere] Plain text or key is not uppercase\n");
        exit(EXIT_FAILURE); 
    }
}
```
This function is explicitly created for the Vigenère's cipher. It is used to check if the key or the plain text is composed of uppercase letters. If that's not the case, the program exits with an error message as shown above. 

<p>&nbsp;</p>


<!-- One-time pad -->
## <center style="color:white;">*One-time pad cipher*</center>
### *Encryption*
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

<p>&nbsp;</p>

### *Decryption*
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


<p>&nbsp;</p>

<p>&nbsp;</p>

<!-- Ceasar's cipher -->
## <center style="color:white;">*Ceasar's cipher*</center>
### *Encryption*
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

<p>&nbsp;</p>

### *Decryption*
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

<p>&nbsp;</p>
<p>&nbsp;</p>

<!-- Vigenère’s cipher -->
## <center style="color:white;">*Vigenère’s cipher*</center>
### *Encryption*
```c
// Vigenère’s cipher
char * vigeneres_cipher_ENCR(char * msg, char * key){
    int k = 0;
    char * keystream = (char *) malloc(strlen(msg)); 
    char * cipherText = (char *) malloc(strlen(msg)); 
    // Generate the keystream
    for(int i=0; i<strlen(msg); i++){
        *(keystream + i) = *(key + k);
        k++;
        if(k == strlen(key)){
            k = 0;
        }
    }
    
    int a_val = (int)'A';                           // value of 'A' in the ASCII table
    for(int i=0; i<strlen(msg); i++){
        spelling_check(msg[i], keystream[i]);       //check for spelling errors
        int plTx_letter_val = (int)*(msg + i); 
        int keystream_letter_val = (int)*(keystream + i); 
        int x_shift = plTx_letter_val - a_val; 
        int y_shift = keystream_letter_val - a_val;
        int res = (x_shift + y_shift) % ALPHABET_SIZE;
        res = res + a_val;
        *(cipherText + i) = (char)res;
    } 
    
    return cipherText;
}
```
This function encrypts a plain text (1st argument) using a secondary string, the key. 
#### ***Keystream***:

First, the key must be the same length as the plain text. Using a loop statement, we copy the key to a new string variable named ```keystream```. The way the loop works is, each character of the key is copied to the "keystream". When the end of the 'key' is reached, the first counter (*k* variable) resets to '0' and the key is copied again from the current position of the "keystream". This process repeats until a condition is matched (```i>=strlen(msg)```), meaning the desired length of "keystream" is achieved. If the key length is greater or equal than the length of the **plain text**, then the key is copied to the "keystream" variable the same way.
```c
for(int i=0; i<strlen(msg); i++){
    *(keystream + i) = *(key + k);
    k++;
    if(k == strlen(key)){
        k = 0;
    }
}
```

Again, using a loop statement, we traverse the characters of the input string (plain text). We check for spelling errors in the key and plain text. 
>To get the shift for the ***x axis***, we subtract the 'A' character ASCII value from the *plain text* character ASCII value to get number between 0-25 (Range of the English alphabet).
```c
int x_shift = plTx_letter_val - a_val; 
```
>The same is done for the ***y axis***, we subtract the 'A' character ASCII value from the *keystream* character ASCII value to get number between 0-25 (Range of the English alphabet). 
```c
int y_shift = keystream_letter_val - a_val;
```
>Adding the two derived values and then using the modulo operator to find the remainder of the division with the number '26' (Length of the English alphabet), we get the ciphered text character value (0-25). <p style="color:red;">Explanation missing!?</p>
To represent it on the ASCII table, the character value is further added the 'A' character ASCII value.
```c
int res = (x_shift + y_shift) % ALPHABET_SIZE;
res = res + a_val;
*(cipherText + i) = (char)res;
```
<p>&nbsp;</p>

### *Decryption*
```c
char * vigeneres_cipher_DECR(char * encMsg, char * key){
    int k = 0;
    char * keystream = (char *) malloc(strlen(encMsg)); 
    char * plainText = (char *) malloc(strlen(encMsg)); 
    // Generate the keystream
    for(int i=0; i<strlen(encMsg); i++){
        *(keystream + i) = *(key + k);
        k++;
        if(k == strlen(key)){
            k = 0;
        }
    }
    
    int a_val = (int)'A';                             // value of 'A' in the ASCII table
    for(int i=0; i<strlen(encMsg); i++){
        int cipTx_letter_val = (int)*(encMsg + i);
        int keystream_letter_val = (int)*(keystream + i); 
        int res = cipTx_letter_val - a_val;
        int y_shift = keystream_letter_val - a_val;
        int x_shift = y_shift - res;
        res = abs(ALPHABET_SIZE - x_shift) % ALPHABET_SIZE;
        *(plainText + i) = (char)(res + a_val);
    } 
    
    return plainText;
}
```
This function is coplementary to ```vigeneres_cipher_DECR(char * encMsg, char * key)```. It dencrypts a ciphered text (1st argument) using a secondary string, the key.

#### ***Keystream***:
The "keystream" string is generated the same way as in the encryption function, explained above. 

Again, using a loop statement, we traverse the characters of the input string (ciphered text). 
>To remove the offset of the ASCII table value, we subtract the 'A' character ASCII value from the *ciphered text* character ASCII value to get number between 0-25 (Range of the English alphabet).
```c
int res = cipTx_letter_val - a_val;
```
>To get the shift for the ***y axis***, as before, we subtract the 'A' character ASCII value from the *keystream* character ASCII value to get number between 0-25 (Range of the English alphabet). 
```c
int y_shift = keystream_letter_val - a_val;
```
>Subtracting the two derived values the **x axis** is produced in a raw form. 
```c
int x_shift = y_shift - res;
```
>To get a usable character from it, the result is subtracted from the value '26' (Length of the English alphabet) and then using the modulo operator to find the remainder of the division with the number '26' (Length of the English alphabet), we get the plain text character value (0-25). <p style="color:red;">Explanation missing!?</p>
```c
res = abs(ALPHABET_SIZE - x_shift) % ALPHABET_SIZE;
```
To represent it on the ASCII table, the character value is further added the 'A' character ASCII value.
```c
*(plainText + i) = (char)(res + a_val);
```

<p>&nbsp;</p>

## License
<p style="color:red;">Apostolos Gioumertakis</p>