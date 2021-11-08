#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "simple_crypto.h"

#define MAX 127                         // max usable character
#define MIN 32                          // min usable character
#define URANDOM_DEVICE "/dev/urandom"

static FILE *urandom;

char * randomKEY;


// Returns a random character (MIN to MAX for ascii table)
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
    // printf("Random char: %c, dec: %d\n", c, c);      //for debugging
    return (char) c;
}

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


int main() {
    urandom = fopen(URANDOM_DEVICE, "rb");
    if (urandom == NULL) {
        fprintf(stderr, "Failed to open %s\n", URANDOM_DEVICE);
        exit(EXIT_FAILURE);
    }

    // char str[] = "apo";
    // char str1[] = "opa";
    // printf("This is str^str1: %d\n", 'a'^'b');
    // printf("Size of str: %d\n", (int)sizeof(str));

    /*** OTP implementation ***/
    char * msg = "test"; 
    char * str = one_time_pad_ENCR(msg);
    printf("[OTP] input: %s\n", msg);  
    printf("[OTP] encrypted: %s\n", str);  
    printf("[OTP] decrypted: %s\n", one_time_pad_DECR(str));  

   
   
    fclose(urandom);
    return 0;
}