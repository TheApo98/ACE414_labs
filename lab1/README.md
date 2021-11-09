# Simple_crypto

Simple_crypto is a cryptographic library, in which, three basic but fundamental cryptographic algorithms are implemented.  (i) One-time pad, (ii) Caesar’s cipher and (iii) Vigenère’s cipher.

## Compilation

To compile the code use the following command:

```bash
make
```

## Functions
### <center>*Random character generator*</center>

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
This function returns a random character every time it's called. The character must be between the MIN and MAX values of the ASCII table and this is accomplished with a ```do{} while()``` loop until we get the desired character.

### <center>*One-time pad cipher*</center>
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

char * one_time_pad_DECR(char * encrMsg){
    char * outputWord = (char *) malloc(strlen(encrMsg)+1); 
    for(int i=0; i<strlen(encrMsg)+1; i++){
        *(outputWord + i) = (char) (*(randomKEY + i) ^ *(encrMsg + i));
    }
    return outputWord;
}
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.
