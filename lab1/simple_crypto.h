
char * one_time_pad_ENCR(char * msg);
char * one_time_pad_DECR(char * encrMsg);
char * ceasars_cipher_ENCR(char * msg, int key);
char * ceasars_cipher_DECR(char * encMsg, int key);
char * vigeneres_cipher_ENCR(char * msg, char * key);
char * vigeneres_cipher_DECR(char * encMsg, char * key);
void spelling_check(char text_lt, char  key_lt);