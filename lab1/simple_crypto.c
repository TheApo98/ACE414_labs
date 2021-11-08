#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "simple_crypto.h"

#define MAX 127                         // max usable character
#define MIN 32                          // min usable character
#define ALPHABET_SIZE 26
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

// Ceasar's cipher
char * ceasars_cipher_ENCR(char * msg, int key){
    char * outputWord = (char *) malloc(strlen(msg)); 
    for(int i=0; i<strlen(msg); i++){
        *(outputWord + i) = (char)((int)*(msg + i) + key);
    }
    return outputWord;
}

char * ceasars_cipher_DECR(char * encMsg, int key){
    char * outputWord = (char *) malloc(strlen(encMsg)); 
    for(int i=0; i<strlen(encMsg); i++){
        *(outputWord + i) = (char)((int)*(encMsg + i) - key);
    }
    return outputWord;
}

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
        // printf("i=%d, k=%d\n", i, k);
    }
    // printf("Keystream: %s\n", keystream);
    
    int a_val = (int)'A';               // value of 'A' in the ASCII table
    for(int i=0; i<strlen(msg); i++){
        int plTx_letter_val = (int)*(msg + i); 
        int keystream_letter_val = (int)*(keystream + i); 
        int x_shift = abs(a_val - plTx_letter_val); 
        int y_shift = abs(a_val - keystream_letter_val);
        int res = (x_shift + y_shift) % ALPHABET_SIZE;
        res = res + a_val;
        *(cipherText + i) = (char)res;
        // printf("i=%d, k=%d\n", i, k);
    } 
    
    return cipherText;
}

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
        // printf("i=%d, k=%d\n", i, k);
    }
    // printf("Keystream: %s\n", keystream);
    
    int a_val = (int)'A';               // value of 'A' in the ASCII table
    for(int i=0; i<strlen(encMsg); i++){
        int cipTx_letter_val = (int)*(encMsg + i);
        int keystream_letter_val = (int)*(keystream + i); 
        int res = cipTx_letter_val - a_val;
        int y_shift = keystream_letter_val - a_val;
        int x_shift = y_shift - res;
        res = abs(ALPHABET_SIZE - x_shift) % ALPHABET_SIZE;
        *(plainText + i) = (char)(res + a_val);
        // printf("i=%d, k=%d\n", i, k);
    } 
    
    return plainText;
}


int main() {
    urandom = fopen(URANDOM_DEVICE, "rb");
    if (urandom == NULL) {
        fprintf(stderr, "Failed to open %s\n", URANDOM_DEVICE);
        exit(EXIT_FAILURE);
    }

    // char str[] = "apo";
    // char str1[] = "opa";
    // printf("This is str: %c and int val: %d\n", *(str1), (int)*(str1));
    // printf("Size of str: %d\n", (int)sizeof(str));

    /*** OTP implementation ***/
    char * msg = "test"; 
    char * str = one_time_pad_ENCR(msg);
    printf("[OTP] input: %s\n", msg);  
    printf("[OTP] encrypted: %s\n", str);  
    printf("[OTP] decrypted: %s\n", one_time_pad_DECR(str));  

    /*** Ceasar's cipher implementation ***/
    msg = "hello"; 
    int key = 4;
    str = ceasars_cipher_ENCR(msg, key);
    printf("[Ceasars] input: %s\n", msg);  
    printf("[Ceasars] key: %d\n", key);  
    printf("[Ceasars] encrypted: %s\n", str);  
    printf("[Ceasars] decrypted: %s\n", ceasars_cipher_DECR(str, key));  
   
    /*** Vigenère’s cipher implementation ***/
    msg = "ATTACKATDAWN"; 
    char *  key1 = "LEMON";
    str = vigeneres_cipher_ENCR(msg, key1);
    printf("[Vigenere] input: %s\n", msg);  
    printf("[Vigenere] key: %s\n", key1);  
    printf("[Vigenere] encrypted: %s\n", str);  
    printf("[Vigenere] decrypted: %s\n", vigeneres_cipher_DECR(str, key1));  
   
    fclose(urandom);
    return 0;
}