#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>

// Added libraries
#include <errno.h>
#include <string.h>

// Declare functions here
void print_hex(unsigned char *data, size_t len);
void print_string(unsigned char *data, size_t len);
int readFromFile(char * filename, unsigned char * data, int * data_len);
int writeToFile(char * filename, unsigned char * data, int data_len);
void formatDateTime(struct tm* tm_ptr, char * date, char * time);



FILE *
fopen(const char *path, const char *mode) 
{

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);



	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);




	return original_fwrite_ret;
}

void formatDateTime(struct tm* tm_ptr, char * date, char * time){
    sprintf(date, "%d/%d/%d", tm_ptr->tm_mday, tm_ptr->tm_mon, tm_ptr->tm_year+1900);
    sprintf(time, "%d:%d:%d", tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);
}

// Useful functions from Assignment 2
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

void print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}

void print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}

