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

#define FILE_CREATE	0
#define FILE_OPEN 	1
#define FILE_WRITE 	2

// To allocate a generous amount of memory
// don't be a cheapskate
#define MAXSIZE  0xFFFF


const char log_file[] = "file_logging.log";

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
int readFromFile(char * filename, unsigned char * data, int * data_len);
int writeToFile(char * filename, unsigned char * data, int data_len);
void formatDateTime(struct tm* tm_ptr, char * date, char * time);
int writeLogsToFile(struct entry logs);
char * getFilename(FILE *fp);
struct tm * getDateTime(time_t t);
void string_to_hex(unsigned char *data, char *out_data, size_t len);



FILE *
fopen64(const char *path, const char *mode) 
{

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	// Code executed before fopen_original
	int file_exists = access(path, F_OK) + 1;

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen64");
	original_fopen_ret = (*original_fopen)(path, mode);

	// If fopen fails, just return?
	if(original_fopen_ret == NULL){
		// File doesn't exist (Probably mode="r+")
		// printf("Error!!! %s, %d\n", strerror(errno), errno);
	    struct entry logs;
		logs.file =  (char *)path;
		logs.time = time(NULL);
		logs.uid = getuid();
		logs.access_type = file_exists;
		// Permission denied
		if(errno == 13)
			logs.action_denied = 1;
		else
			logs.action_denied = 0;
		logs.fingerprint = "00000000000000000000000000000000";
		if(writeLogsToFile(logs) == -1){
			fprintf(stderr, "Error!!! %s.\n", strerror(errno));
			exit(EXIT_FAILURE);
		}
		else{
			// printf("[fopen] Writing logs successful\n");
		}
		return original_fopen_ret;
	}

	
	// Create entry struct
    struct entry logs;
	// logs.file = (char *)path;
	logs.file = getFilename(original_fopen_ret);
    logs.time = time(NULL);
	logs.uid = getuid();
	logs.access_type = file_exists;
	// If you got to this point, you have access
	logs.action_denied = 0;
	
	// File can be ignored
	// if(!strcmp(logs.file, "/etc/ssl/openssl.cnf")){
	// 	return original_fopen_ret;
	// }

	// The MD5 hash from the file
    unsigned char* md5_hash = (unsigned char*)malloc(sizeof(char)*MD5_DIGEST_LENGTH);
    unsigned char* data = (unsigned char*)malloc(sizeof(char)*MAXSIZE);
	size_t data_len = 0;
	if(readFromFile(logs.file, data, (int*)&data_len) == 1){
        fprintf(stderr, "Error reading from file, errno: \n%s!\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
    // printf("After readFromFile\n");
    // print_string(data, data_len);

	logs.fingerprint = (char*)malloc(sizeof(char)*(MD5_DIGEST_LENGTH*2));
	// If there are data in the file, generate MD5 hash.....
	if(data_len > 0){
		MD5(data, data_len, md5_hash);
		string_to_hex(md5_hash, logs.fingerprint, MD5_DIGEST_LENGTH);
	}
	//... if not, hash = '0'
	else 
		memcpy(logs.fingerprint, "00000000000000000000000000000000", MD5_DIGEST_LENGTH*2);

    if(writeLogsToFile(logs) == -1){
		fprintf(stderr, "Error!!! %s.\n", strerror(errno));
        exit(EXIT_FAILURE);
	}
	else{
		// printf("[fopen] Writing logs successful\n");
	}
	free(data);
	free(md5_hash);
	free(logs.file);
	free(logs.fingerprint);

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
	
	// Flush the output to file so we can read the new data
	// We can't wait for fclose, we need them now!!!
	fflush(stream);

	// If fopen fails, just return?
	// if(original_fwrite_ret == (int)nmemb)
	// 	return original_fwrite_ret;
	
	// Create entry struct
    struct entry logs;

	logs.file = getFilename(stream);
    logs.time = time(NULL);

    // printf("After Time\n");

	logs.uid = getuid();
	logs.access_type = 2;

	// Compare current uid and file uid
	if(original_fwrite_ret < (int)nmemb)
		logs.action_denied = 1;
    else
        logs.action_denied = 0;
    // printf("After action_denied_flag\n");
    
	// The MD5 hash from the file
    unsigned char* md5_hash = (unsigned char*)malloc(sizeof(char)*MD5_DIGEST_LENGTH);
    unsigned char* data = (unsigned char*)malloc(sizeof(char)*MAXSIZE);
	size_t data_len = 0;
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
	else{
		// printf("[fwrite] Writing logs successful\n");
	}
	free(data);
	free(md5_hash);
	free(logs.file);
	free(logs.fingerprint);

	return original_fwrite_ret;
}


/* My custom functions */

char * getFilename(FILE *fp){
    int filedes = fileno(fp);
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
    // printf("File Name: %s\n", filename);
	
	// // Calculate relative path
    // char * relative_path = (char *)malloc(sizeof(char)*MAXSIZE);
    // char * token;
	// token = strtok(filename, "/");
	// while( token != NULL ) {
	// 	strcpy(relative_path , token);
	// 	token = strtok(NULL, "/");
	// }
    // free(filename);
    // return relative_path;
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
    sprintf(date, "%02d-%02d-%d", tm_ptr->tm_mday, tm_ptr->tm_mon+1, tm_ptr->tm_year+1900);
    sprintf(time, "%02d:%02d:%02d", tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);
}

int writeLogsToFile(struct entry logs){
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	int file_exists = access(log_file, F_OK) + 1;
	
	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(log_file, "a");

    if(original_fopen_ret == NULL){
        return 1;
    }
    
	
	int wr_err = 0;
	if(!file_exists){
		wr_err = fprintf(original_fopen_ret, "UID | Filename | Date | Time | Access_Type | Action_Denied | Fingerprint |\n");
	}

    char * date = malloc(sizeof(char)*15);
    char * time = malloc(sizeof(char)*15);
    formatDateTime(getDateTime(logs.time), date, time);

	wr_err = fprintf(original_fopen_ret, "%d|", logs.uid);
	wr_err = fprintf(original_fopen_ret, "%s|", logs.file);
	wr_err = fprintf(original_fopen_ret, "%s|", date);
	wr_err = fprintf(original_fopen_ret, "%s|", time);
	wr_err = fprintf(original_fopen_ret, "%d|", logs.access_type);
	wr_err = fprintf(original_fopen_ret, "%d|", logs.action_denied);
	wr_err = fprintf(original_fopen_ret, "%s|\n", logs.fingerprint);
	free(date);
	free(time);
	fclose(original_fopen_ret);
	// Give permission for all users to write to the log file
	chmod(log_file,  S_IWUSR|S_IWOTH|S_IWGRP | S_IRUSR|S_IROTH|S_IRGRP );	// wr-wr-wr-
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
        return 1;
    }
    /* File commands */ 
    /* (necessary for reading special characters like EOF, etc) */
    fseek(original_fopen_ret, 0, SEEK_END);     // go to file end
    *data_len = ftell(original_fopen_ret);           // calculate the file size
    rewind(original_fopen_ret);                 // go to file start and...
    if(fread(data, *data_len, sizeof(unsigned char), original_fopen_ret) < 0){
        fclose(original_fopen_ret);
        return 1;
    }
    fclose(original_fopen_ret);
    return 0;
}

// A modified version of print_hex, to convert MD5 hash to a hex string
void string_to_hex(unsigned char *data, char *out_data, size_t len)
{
	size_t i;
	size_t j;

	if (data) {
        j=0;
		for (i = 0;  i < len; i++) {
			// if (!(i % 16) && (i != 0))
			// 	printf("\n");
			sprintf((out_data+j),"%02X", data[i]);
            j+=2;
		}
		// printf("\n");
	}
}
