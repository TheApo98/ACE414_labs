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




## License
<p style="color:red;">Apostolos Gioumertakis</p>