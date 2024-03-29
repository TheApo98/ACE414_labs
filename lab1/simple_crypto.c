#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "simple_crypto.h"

#define MAX 127                         // max usable character
#define MIN 0                           // min usable character
#define ALPHABET_SIZE 26
#define NUM_SIZE 10
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
    return (char) c;
}

// One-time pad
char * one_time_pad_ENCR(char * msg){
    randomKEY = (char *) malloc(sizeof(char)*strlen(msg));
    char * outputWord = (char *) malloc(sizeof(char)*strlen(msg)); 
    for(int i=0; i<strlen(msg); i++){
        *(randomKEY + i) = random_char(); 
        *(outputWord + i) = (char) (*(randomKEY + i) ^ *(msg + i));
    }
    return outputWord;
}

char * one_time_pad_DECR(char * encrMsg){
    char * outputWord = (char *) malloc(sizeof(char)*strlen(encrMsg)); 
    for(int i=0; i<strlen(encrMsg); i++){
        *(outputWord + i) = (char) (*(randomKEY + i) ^ *(encrMsg + i));
    }
    free(randomKEY);
    return outputWord;
}

// Ceasar's cipher
char * ceasars_cipher_ENCR(char * msg, int key){
    char * cipherText = (char *) malloc(sizeof(char)*strlen(msg)); 
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

char * ceasars_cipher_DECR(char * encMsg, int key){
    char * plainText = (char *) malloc(sizeof(char)*strlen(encMsg)); 
    int charVal = 0;
    for(int i=0; i<strlen(encMsg); i++){
        charVal = (int)encMsg[i];
        if(encMsg[i] >= 'A' && encMsg[i] <= 'Z'){
            charVal = charVal - 'A';
            if(charVal - key < 0)
                *(plainText + i) = abs((abs(charVal - key) % ALPHABET_SIZE) - ALPHABET_SIZE) + 'A';
            else
                *(plainText + i) = (abs(charVal - key) % ALPHABET_SIZE) + 'A';
        }
        else if(encMsg[i] >= 'a' && encMsg[i] <= 'z'){
            charVal = charVal - 'a';
            if(charVal - key < 0)
                *(plainText + i) = abs((abs(charVal - key) % ALPHABET_SIZE) - ALPHABET_SIZE) + 'a';
            else
                *(plainText + i) = (abs(charVal - key) % ALPHABET_SIZE) + 'a';
        }
        else if(isdigit(encMsg[i]) != 0){
            charVal = charVal - '0';
            if(charVal - key < 0)
                *(plainText + i) = abs((abs(charVal - key) % NUM_SIZE) - NUM_SIZE) + '0';
            else
                *(plainText + i) = (abs(charVal - key) % NUM_SIZE) + '0';
        }
        else
            *(plainText + i) = *(encMsg + i);
    }
    return plainText;
}

// Vigenère’s cipher
char * vigeneres_cipher_ENCR(char * msg, char * key){
    int k = 0;
    char * keystream = (char *) malloc(sizeof(char)*strlen(msg)); 
    char * cipherText = (char *) malloc(sizeof(char)*strlen(msg)); 
    // Generate the keystream
    for(int i=0; i<strlen(msg); i++){
        *(keystream + i) = *(key + k);
        k++;
        if(k == strlen(key)){
            k = 0;
        }
    }
    
    int a_val = (int)'A';                           // value of 'A' in the ASCII table
    int plTx_letter_val, keystream_letter_val = 0;
    int x_shift, y_shift, res = 0;
    for(int i=0; i<strlen(msg); i++){
        spelling_check(msg[i], keystream[i]);       //check for spelling errors
        plTx_letter_val = (int)*(msg + i); 
        keystream_letter_val = (int)*(keystream + i); 
        x_shift = plTx_letter_val - a_val; 
        y_shift = keystream_letter_val - a_val;
        res = (x_shift + y_shift) % ALPHABET_SIZE;
        res = res + a_val;
        *(cipherText + i) = (char)res;
    } 
    
    return cipherText;
}

char * vigeneres_cipher_DECR(char * encMsg, char * key){
    int k = 0;
    char * keystream = (char *) malloc(sizeof(char)*strlen(encMsg)); 
    char * plainText = (char *) malloc(sizeof(char)*strlen(encMsg)); 
    // Generate the keystream
    for(int i=0; i<strlen(encMsg); i++){
        *(keystream + i) = *(key + k);
        k++;
        if(k == strlen(key)){
            k = 0;
        }
    }
    
    int a_val = (int)'A';                           // value of 'A' in the ASCII table
    // variable initialization
    int cipTx_letter_val, keystream_letter_val = 0;
    int res, x_shift, y_shift = 0;
    for(int i=0; i<strlen(encMsg); i++){
        cipTx_letter_val = (int)*(encMsg + i);
        keystream_letter_val = (int)*(keystream + i); 
        res = cipTx_letter_val - a_val;
        y_shift = keystream_letter_val - a_val;
        x_shift = y_shift - res;
        res = abs(ALPHABET_SIZE - x_shift) % ALPHABET_SIZE;
        *(plainText + i) = (char)(res + a_val);
    } 
    
    return plainText;
}

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


int main() {
    urandom = fopen(URANDOM_DEVICE, "rb");
    if (urandom == NULL) {
        fprintf(stderr, "Failed to open %s\n", URANDOM_DEVICE);
        exit(EXIT_FAILURE);
    }

    /*** OTP implementation ***/
    char * msg = (char *) malloc(sizeof(char)*100); 
    printf("[OTP] input: ");  
    scanf("%s", msg);
    printf("[OTP] encrypted(decimal): ");  
    char * str = one_time_pad_ENCR(msg);
    for (int i = 0; i<strlen(str); i++)
    {
        printf("[%d] ", str[i]);
    }
    printf("\n");
    printf("[OTP] decrypted: %s\n", one_time_pad_DECR(str));  

    /*** Ceasar's cipher implementation ***/
    int key = 0;
    printf("[Ceasars] input: "); 
    scanf("%s", msg);
    printf("[Ceasars] key: ");
    scanf("%d", &key);  
    str = ceasars_cipher_ENCR(msg, key);
    printf("[Ceasars] encrypted: %s\n", str);  
    printf("[Ceasars] decrypted: %s\n", ceasars_cipher_DECR(str, key));  
   
    /*** Vigenère’s cipher implementation ***/
    char * key1 = (char *) malloc(sizeof(char)*100); 
    
    printf("[Vigenere] input: ");  
    scanf("%s", msg);
    printf("[Vigenere] key: ");
    scanf("%s", key1);
    str = vigeneres_cipher_ENCR(msg, key1);
    printf("[Vigenere] encrypted: %s\n", str);  
    printf("[Vigenere] decrypted: %s\n", vigeneres_cipher_DECR(str, key1));  
   
    fclose(urandom);
    return 0;
}