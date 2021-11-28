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

struct entry {

	int uid; /* user id (positive integer) */
	char *file; /* filename (string) */

	// time_t date; /* file access date */
	time_t time; /* file access time */

	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	char *fingerprint; /* file fingerprint */

};

// Declare functions here
void print_hex(unsigned char *data, size_t len);
void print_string(unsigned char *data, size_t len);
int readFromFile(char * filename, unsigned char * data, int * data_len);
int writeToFile(char * filename, unsigned char * data, int data_len);
void formatDateTime(struct tm* tm_ptr, char * date, char * time);
int writeLogsToFile(struct entry logs);
char * getFilename(FILE *fp);
struct tm * getDateTime(time_t t);
void string_to_hex(unsigned char *data, char *out_data, size_t len);



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


	// Get file stats
	struct stat stats;
    int filedes = fileno(original_fopen_ret);
    if(fstat(filedes, &stats) == -1){
        fprintf(stderr, "Stat() failed: \n%s!\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
	
	// Create entry struct
    struct entry logs;

	logs.file = (char *)path;
	logs.file = getFilename(original_fopen_ret);
    logs.time = time(NULL);

    // printf("After Time\n");

	logs.uid = getuid();
	logs.access_type = access(logs.file, F_OK) + 1;

	// Compare current uid and file uid
	if(stats.st_uid != logs.uid)
		logs.action_denied = 1;
    else
        logs.action_denied = 0;
    // printf("After action_denied_flag\n");
    

	// The MD5 hash from the file
    unsigned char* md5_hash = (unsigned char*)malloc(MD5_DIGEST_LENGTH);
    unsigned char* data = (unsigned char*)malloc(sizeof(char)*256);
	size_t data_len = 0;
	printf("Before readFromFile in fopen\n");
	printf("File: %s\n", logs.file);
	if(readFromFile(logs.file, data, (int*)&data_len) == 1){
        fprintf(stderr, "Error reading from file, errno: \n%s!\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    // printf("After readFromFile\n");
    // print_string(data, data_len);

    MD5(data, data_len, md5_hash);
    // logs.fingerprint = (char *)md5_hash;
	logs.fingerprint = (char*)malloc(sizeof(char)*(MD5_DIGEST_LENGTH*2));
	string_to_hex(md5_hash, logs.fingerprint, MD5_DIGEST_LENGTH);
    // printf("After MD5\n");

    if(writeLogsToFile(logs) == -1){
		fprintf(stderr, "Error!!! %s.\n", strerror(errno));
        exit(EXIT_FAILURE);
	}
	else
		printf("Write successful\n");

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
	if(original_fwrite_ret == (int)nmemb)
		return original_fwrite_ret;

	// Get file stats
	struct stat stats;
    int filedes = fileno(stream);
    if(fstat(filedes, &stats) == -1){
        fprintf(stderr, "Stat() failed: \n%s!\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
	
	// Create entry struct
    struct entry logs;

	logs.file = getFilename(stream);
    logs.time = time(NULL);

    // printf("After Time\n");

	logs.uid = getuid();
	logs.access_type = 2;

	// Compare current uid and file uid
	if(stats.st_uid != logs.uid)
		logs.action_denied = 1;
    else
        logs.action_denied = 0;
    // printf("After action_denied_flag\n");
    

	// The MD5 hash from the file
    unsigned char* md5_hash = (unsigned char*)malloc(MD5_DIGEST_LENGTH);
    unsigned char* data = (unsigned char*)malloc(sizeof(char)*256);
	size_t data_len = 0;
	printf("Before readFromFile in fwrite\n");
	if(readFromFile(logs.file, data, (int*)&data_len) == 1){
        fprintf(stderr, "Error reading from file, errno: \n%s!\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    // printf("After readFromFile\n");
    // print_string(data, data_len);

    MD5(data, data_len, md5_hash);
	logs.fingerprint = (char*)malloc(sizeof(char)*(MD5_DIGEST_LENGTH*2));
	string_to_hex(md5_hash, logs.fingerprint, MD5_DIGEST_LENGTH);
    // logs.fingerprint = (char *)md5_hash;
    // printf("After MD5\n");

    if(writeLogsToFile(logs) == -1){
		fprintf(stderr, "Error!!! %s.\n", strerror(errno));
        exit(EXIT_FAILURE);
	}
	else
		printf("Write successful\n");

	free(data);
	free(md5_hash);


	return original_fwrite_ret;
}


/* My custom functions */

char * getFilename(FILE *fp){
    int filedes = fileno(fp);
    int MAXSIZE = 0xFFF;
    char * proclnk = (char *)malloc(sizeof(char)*MAXSIZE);
    char * filename = (char *)malloc(sizeof(char)*MAXSIZE);
    sprintf(proclnk, "/proc/self/fd/%d", filedes);
    int r = readlink(proclnk, filename, MAXSIZE);
    if (r < 0)
    {
        printf("Failed to readlink\n");
        free(proclnk);
        free(filename);
        exit(1);
    }
    filename[r] = '\0';
    free(proclnk);
    // free(filename);
    // printf("File Name: %s\n", filename);
    return filename;
}

// Date and time
struct tm * getDateTime(time_t t){
	struct tm* tm_ptr;
	// Convert it to local time and fill the struct
    tm_ptr = localtime(&t);
	// Convert using struct to human readable string
    // char * dateTime = asctime(tm_ptr);
    return tm_ptr;
}

void formatDateTime(struct tm* tm_ptr, char * date, char * time){
    sprintf(date, "%02d-%02d-%d", tm_ptr->tm_mday, tm_ptr->tm_mon, tm_ptr->tm_year+1900);
    sprintf(time, "%02d:%02d:%02d", tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);
}

int writeLogsToFile(struct entry logs){
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)("file_logging.log", "a");

    if(original_fopen_ret == NULL){
        return 1;
    }
    
    char * date = malloc(sizeof(char)*15);
    char * time = malloc(sizeof(char)*15);
    formatDateTime(getDateTime(logs.time), date, time);

	int wr_err = 0;
	wr_err = fprintf(original_fopen_ret, "%d|", logs.uid);
	wr_err = fprintf(original_fopen_ret, "%s|", logs.file);
	wr_err = fprintf(original_fopen_ret, "%s|", date);
	wr_err = fprintf(original_fopen_ret, "%s|", time);
	wr_err = fprintf(original_fopen_ret, "%d|", logs.access_type);
	wr_err = fprintf(original_fopen_ret, "%d|", logs.action_denied);
	// wr_err = fwrite(logs.fingerprint , sizeof(unsigned char) , MD5_DIGEST_LENGTH , original_fopen_ret );
	wr_err = fprintf(original_fopen_ret, "%s|\n", logs.fingerprint);
	free(date);
	free(time);
	fclose(original_fopen_ret);
	if (wr_err < 0){ 
		return -1;
    }
	return 0;
}

// Useful functions from Assignment 2
int readFromFile(char * filename, unsigned char * data, int * data_len){
    // FILE *fp;
   	// fp = fopen(filename, "rb");
    
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(filename, "rb");
	
	if(original_fopen_ret == NULL){
		printf("After original_fopen_ret == NULL\n");
        return 1;
    }
    /* File commands */ 
    /* (necessary for reading special characters like EOF, etc) */
    fseek(original_fopen_ret, 0, SEEK_END);     // go to file end
    *data_len = ftell(original_fopen_ret);           // calculate the file size
    rewind(original_fopen_ret);                 // go to file start and...
    if(fread(data, *data_len, sizeof(unsigned char), original_fopen_ret) == 0){
        fclose(original_fopen_ret);
		printf("Data: %s\n", data);
        return 1;
    }
    fclose(original_fopen_ret);
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

void string_to_hex(unsigned char *data, char *out_data, size_t len)
{
	size_t i;
	size_t j;

	if (data) {
        j=0;
		for (i = 0;  i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			sprintf((out_data+j),"%02X", data[i]);
            j+=2;
		}
		// printf("\n");
	}
}
