# Assignment_3: Access Control Logging

In this assignment you are going to develop three(3) tools: 
1. **Access Control Logging:**\
   Log every users access to files on the system, by intercepting fopen() and fwrite() and
   generating a log file.
2. **Access Control Log Monitoring:**\
   Parse the log file generated and extract all incidents where malicious users tried to access multiple files (7 or more) without having permissions.\
   Given a filename, the log monitoring tool should track and report all users that have accessed the specific file. By comparing the digital fingerprints/hash values, the log monitoring tool should check how many times the file was indeed modified.
3. **Access Control Logging & Log Monitoring testing tool:**\
   A simple tool that is used to test and demonstrate the above tasks.
 

## Compilation

To compile the code, use the following command:

```bash
make all
```

To run the code, use the following commands:

```bash
make run

./acmonitor
```

## GCC version
To get the version of the gcc compiler, run:
```bash
# Command 
    gcc --version

# Result
    gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
```

## Usage
Help menu of the *Access Control Log Monitoring* tool:
```
./acmonitor -h

usage:
        ./acmonitor
Options:
-m, Prints malicious users
-i <filename>, Prints table of users that modified the file <filename> and the number of modifications
-h, Help message
```

<p>&nbsp;</p>

## 1) Access Control Logging tool

## <center>*Fopen() function*</center>
```c
FILE * fopen(const char *path, const char *mode); 
```
This is a modified version fo fopen(), used to keep trace of every file access from users in the system. In the beginning, a function pointer to the original ```fopen()``` is declared. After that, we call the original ```fopen()``` function but first we check if the file to be opened exists. The arguments of our function are passes to the original one. \
If the return value of the original function is *NULL* (usually because we try to read without the file existing or because permission is denied), start logging the following information: UID, Filename, Date, Time, Access Type, Action-denied flag and File fingerprint. The variables get assigned as seen in the code and the ```access_type``` variable is assigned with the value of ```file_exists``` variable ('0'=>Create '1'=>Open) and the fingerprint is set to '0'. When the error returned from original ```fopen()``` is "Permission denied" (errno=13), the Action-denied flag = '1',  else Action-denied flag = '0'. Then the information is stored (appended) to the log file using the function "writeLogsToFile(logs)" . \
If the return value is not *NULL*, we log the same information as before, except for the fingerprint, which is derived from hashing the data store in the file with the MD5 algorithm. If the data in the file to be opened have length greater than 0, then the MD5 hash is calculated and passed to the fingerprint variable. If thats not the case, the fingerprint is set to '0'. The Action-denied flag is set '0' (there is no other case) and then all the information is stored (appended) to the log file using the function "writeLogsToFile(logs)" 
 
## <center>*Fwrite() function*</center>
```c
size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
```
This is a modified version fo fwrite(), used to keep trace of every file access from users in the system. In the beginning, a function pointer to the original ```fwrite()``` is declared. After that, we call the original ```fwrite()``` function and the arguments of our function are passes to the original one. \
The same information is logged as in ```fopen()``` with the exception of the variable ```access_type``` which is set to '2' for file writing. Also if the value returned from original ```fwrite()``` is less than the value of the argument ```nmemb```, then the action_denied flag is set to '1' (fwrite failed). \
The fingerprint is generated the same way as before, by reading all the data in the file and calculating the MD5 hash. This wouldn't be possible without the ```fflush(FILE *stream)``` function, which writes the data in the file without the need of the ```fclose()```. Then the all the information (including the MD5 hash), is stored to the log file using yet again , the function "writeLogsToFile(logs)". And the function returns.
 
<p>&nbsp;</p>


## Utility Functions
We needed to construct some helper functions for reading from files, writing to files,  getting the current time and more.

## <center>*getFilename*</center>
```c
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
    // printf("File Name: %s\n", filename);
	
    char * relative_path = (char *)malloc(sizeof(char)*MAXSIZE);
    char * token;
	token = strtok(filename, "/");
	while( token != NULL ) {
		strcpy(relative_path , token);
		token = strtok(NULL, "/");
	}
    free(filename);
    return relative_path;
    // return filename;
}
```
```c
// Date and time
struct tm * getDateTime(time_t t){
	struct tm* tm_ptr;
	// Convert it to local time and fill the struct
    tm_ptr = localtime(&t);
	// Convert using struct to human readable string
    // char * dateTime = asctime(tm_ptr);
    return tm_ptr;
}
```
```c
void formatDateTime(struct tm* tm_ptr, char * date, char * time){
    sprintf(date, "%02d-%02d-%d", tm_ptr->tm_mday, tm_ptr->tm_mon, tm_ptr->tm_year+1900);
    sprintf(time, "%02d:%02d:%02d", tm_ptr->tm_hour, tm_ptr->tm_min, tm_ptr->tm_sec);
}
```
```c
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
```

## <center>*Read from file*</center>
```c
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
```
>This function is used to read bytes from a file. It is used both for the plain and cipher text. It takes as input three(3) arguments, the filename, a pointer to store the data and a pointer  for the length of the data (call by reference).<br>
This function seeks for the end of the file to calculate the size of the data it contains and then using ```fread()```  function, reads the entire file (using the data_len as input) and store the data into a buffer.<br>
If an error is encountered, returns 1 or if the read is successful, returns 0;

```c
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
```

<p>&nbsp;</p>
<p>&nbsp;</p>

## 3) Test the Access Control Logging & Log Monitoring tools

```c
for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}
```
Using the test_aclog.c file we create 10 files using "fopen()" and their filename get writen in them using "fwrite()". 


```c
for (i = 0; i < 10; i++) {
		chmod(filenames[i],  S_IRUSR|S_IROTH|S_IRGRP );	// -r--r--r-
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}
```
Then the permission of the files is changed to read-only and we try to open these files with write permission and then write to them. The result is the display of the "fopen error" message and the appropriate entries in the log file. 

```c
for (i = 0; i < 10; i++) {
		chmod(filenames[i],  S_IWUSR|S_IWOTH|S_IWGRP | S_IRUSR|S_IROTH|S_IRGRP );	// wr-wr-wr-
		file = fopen(filenames[i], "r");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}
```
Then the permission of the files is changed to read and write and the program is able to open and write to the files without any problems. Again and the appropriate entries are stored in the log file.

```c
for (i = 0; i < 10; i++) {
		chmod(filenames[i],  S_IWUSR|S_IWOTH|S_IWGRP | S_IRUSR|S_IROTH|S_IRGRP );	// wr-wr-wr-
		file = fopen(filenames[i], "a+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}
```
Finally we append data to the files (their filename) in order to change the MD5 hash and get the corresponding entries in the log file. 






<p>&nbsp;</p>


## License
<p style="color:red;">Apostolos Gioumertakis</p>