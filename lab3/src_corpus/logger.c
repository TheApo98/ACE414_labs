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
int writeLogsToFile(int user_id, char* filename, char* date, char* time, 
	int access_type, int action_denied_flag, unsigned char* md5_hash);



FILE *
fopen(const char *path, const char *mode) 
{

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	// If fopen fails, just return?
	if(original_fopen_ret == NULL)
		return original_fopen_ret;

	uid_t user_id = getuid();
	char * filename = path;

	// Get file stats
	struct stat stats;
    int filedes = fileno(original_fopen_ret);
    if(fstat(filedes, &stats) == -1){
        fprintf(stderr, "Stat() failed: \n%s!\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
	
	// Date and time
	struct tm* tm_ptr;
    time_t t;
	// Epoch time (in seconds) of last access
    t = stats.st_atim.tv_sec;
	// Convert it to local time and fill the struct
    tm_ptr = localtime(&t);
	// Convert using struct to human readable string
    // char * dateTime = asctime(tm_ptr);
	char * date = malloc(sizeof(char)*50);
    char * time = malloc(sizeof(char)*50);
    formatDateTime(tm_ptr, date, time);

	int access_type = access(path, F_OK) + 1;

	// If action is NOT denied --> '0' else '1'
	int action_denied_flag = 0;
	if(stats.st_uid != user_id)
		action_denied_flag = 1;

	// The MD5 hash from the file
    unsigned char* md5_hash = (unsigned char*)malloc(MD5_DIGEST_LENGTH);
    unsigned char* data = (unsigned char*)malloc(sizeof(char)*256);
	size_t data_len = 0;
	if(readFromFile(filename, data, (int*)&data_len) == 1){
        fprintf(stderr, "Error reading from file, errno: \n%s!\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

	// Calculate the MD5 hash
    MD5(data, data_len, md5_hash);

	// Write log to file
	if(writeLogsToFile(user_id, filename, date, time, access_type, action_denied_flag, md5_hash) == -1){
		fprintf(stderr, "Error!!! %s.\n", strerror(errno));
        exit(EXIT_FAILURE);
	}
	else
		printf("Write successful\n");

	free(date);
	free(time);
	free(data);
	free(md5_hash);

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


	// If fopen fails, just return?
	if(original_fwrite_ret == NULL)
		return original_fwrite_ret;

	uid_t user_id = getuid();

	// Get filename from file pointer
    int MAXSIZE = 0xFFF;
    char proclnk[0xFFF];
    int filedes = fileno(stream);
    char filename[0xFFF];
	sprintf(proclnk, "/proc/self/fd/%d", filedes);
	int r = readlink(proclnk, filename, MAXSIZE);
	if (r < 0)
	{
		printf("failed to readlink\n");
		exit(1);
	}
	filename[r] = '\0';
    // printf("File Name: %s\n", filename);

	// Get file stats
	struct stat stats;
    int filedes = fileno(original_fwrite_ret);
    if(fstat(filedes, &stats) == -1){
        fprintf(stderr, "Stat() failed: \n%s!\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
	
	// Date and time
	struct tm* tm_ptr;
    time_t t;
	// Epoch time (in seconds) of last access
    t = stats.st_atim.tv_sec;
	// Convert it to local time and fill the struct
    tm_ptr = localtime(&t);
	// Convert using struct to human readable string
    // char * dateTime = asctime(tm_ptr);
	char * date = malloc(sizeof(char)*50);
    char * time = malloc(sizeof(char)*50);
    formatDateTime(tm_ptr, date, time);

	// Access type for writing
	int access_type = 2;

	// If action is NOT denied --> '0' else '1'
	int action_denied_flag = 0;
	if(stats.st_uid != user_id)
		action_denied_flag = 1;

	// The MD5 hash from the file
    unsigned char* md5_hash = (unsigned char*)malloc(MD5_DIGEST_LENGTH);
    unsigned char* data = (unsigned char*)malloc(sizeof(char)*256);
	size_t data_len = 0;
	if(readFromFile(filename, data, (int*)&data_len) == 1){
        fprintf(stderr, "Error reading from file, errno: \n%s!\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

	// Calculate the MD5 hash
    MD5(data, data_len, md5_hash);

	// Write log to file
	if(writeLogsToFile(user_id, filename, date, time, access_type, action_denied_flag, md5_hash) == -1){
		fprintf(stderr, "Error!!! %s.\n", strerror(errno));
        exit(EXIT_FAILURE);
	}
	else
		printf("Write successful\n");

	free(date);
	free(time);
	free(data);
	free(md5_hash);


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

int writeLogsToFile(int user_id, char* filename, char* date, char* time, int access_type, int action_denied_flag, unsigned char* md5_hash){
	FILE *fp1 = fopen("file_logging.log", "a");
	if(fp1 == NULL)
		return -1;

	int wr_err = 0;
	wr_err = fprintf(fp1, "UID: %d\n", user_id);
	wr_err = fprintf(fp1, "File name: %s\n", filename);
	wr_err = fprintf(fp1, "Date: %s\n", date);
	wr_err = fprintf(fp1, "Timestamp: %s\n", time);
	wr_err = fprintf(fp1, "Access Type: %d\n", access_type);
	wr_err = fprintf(fp1, "Action denied flag: %d\n", action_denied_flag);
	wr_err = fprintf(fp1, "Fingerprint(MD5): ");
	wr_err = fwrite(md5_hash , sizeof(unsigned char) , MD5_DIGEST_LENGTH , fp1 );
	wr_err = fprintf(fp1, "\n\n");
	if (wr_err < 0) 
		return -1;
	fclose(fp1);
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

