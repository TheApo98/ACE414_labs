# Assignment_5: Implement a basic ransomware

In this assignment you are going to develop three(3) tools: 
1. **Ransomware**\
   A bash script that creates, encrypts and deletes the original files inside a specific directory in a certain amount of time.
2. **Access Control Logging:**\
   Same as in Assignment 3. Log every users access to files on the system, by intercepting fopen64() and fwrite() and
   generating a log file.
3. **Access Control Log Monitoring:**\
   Same as in Assignment 3. Parse the log file generated and extract all incidents where malicious users tried to access multiple files (7 or more) without having permissions.\
   Given a filename, the log monitoring tool should track and report all users that have accessed the specific file. By comparing the digital fingerprints/hash values, the log monitoring tool should check how many times the file was indeed modified.\
   In addition to that, the tool should find all the files created in the last 20 minutes. Also, it should find all the files with the suffix ".encrypt"


## GCC version
To get the version of the gcc compiler, run:
```bash
# Command 
    gcc --version

# Result
    gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
```


## Compilation

To compile the code, use the following command:

```bash
make all
```

To execute the ransomware.sh use the following command:
```bash
./ransomware.sh
```

To run the **Access Control Log Monitoring** tool, use the following commands:

```bash
./acmonitor
```

## Usage

Help menu of the *Ransomware*:
```
$ ./ransomware.sh -h

 Usage:
 ./ransomware.sh -d DIRECTORY -f NUM_OF_FILES -m [0|1|2]
 ./ransomware.sh -h

 Options:
        -d path , Path to the directory with files
        -f <ΙΝΤ> , The number of files to be encrypted
        -h , This help message
        -m [0|1|2], 0=create, 1=encrypt-delete, 2=decrypt-delete
```

Help menu of the *Access Control Log Monitoring* tool:
```
$ ./acmonitor -h

usage:
        ./acmonitor
Options:
-m, Prints malicious users
-i <filename>, Prints table of users that modified the file <filename> and the number of modifications
-v <number of files>, Prints the total number of files created in the last 20 minutes
-e, Prints all the files that were encrypted by the ransomware
-h, Help message
```

<p>&nbsp;</p>

## 1) Ransomware
This "tool" is a bash script executing specific tasks such as:
1. Creating/selecting the files to be encrypted
2. Encrypting and then deleting the original files
3. Decryption of the encrypted files

A directory is specified through the use of arguments, so that the files can be created inside there. Every file creation and writing is logged by the system with the help of the **Access Control Logging** tool, implemented in the "logger.so" library (better description below).

The command "export LD_PRELOAD=./logger.so" is used to dynamically link the shared library and intercept both Openssl library for encryption/decryption and the "test_aclog.c" for logging the creation of files. 

The script only creates files with the format: "file_[0-9]*.txt". Every other file in the specified directory is ignored. Also, to encrypt the files, the ransomware looks for this filename format, and only encrypts and deletes the files up to the number (-f option) provided by the user. 

In any case, if the specified directory or the filenames don't exist, the script outputs an error and terminates. 

<p>&nbsp;</p>


## 2) Access Control Logging tool


In this step, we changed the implementation of **Assignment 3**. Instead of intercepting ```fopen()``` , we now also intercept ```fopen64()``` , used by the Openssl library. \
In order to intercept both functions, the following function was used: 
```c
FILE * fopen64(const char *path, const char *mode) {
	return fopen(path, mode);
}
```
Using the code above, solved some issues I encountered while creating files with ```fopen64()``` and the writing data to them using ```fwrite()``` in the "test_aclog.c" file. Instead of using ```fopen64()``` , ```fopen()``` is now used to create the files and the first is "reserved" for the encryption using the Openssl library.  

Below are the functions created in **Assignment 3**, described in detail.
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

## 3) Access Control Log Monitoring
On top of the functionality implemented in the Assignment 3, two (2) more functions were created to meet the requirements of this Assignment.

## <center>*List all files created in the last 20 minutes*</center>

```c
void list_tot_number_of_files_20min(FILE *log, int number_of_files);
```
This function reads all the log entries and looks for files created in the last 20 minutes. If the number of logged files exceeds the-provided-as-argument number, then the program reports the results, the total amount of files created and their filenames.

Example:
```bash
$ ./acmonitor -v 3
Files created less than 20 minutes ago: 4
Show their filenames? (y-n) y
/home/apo/ACE414_labs/lab5/src_corpus/files/file_0.txt.encrypt
/home/apo/ACE414_labs/lab5/src_corpus/files/file_1.txt.encrypt
/home/apo/ACE414_labs/lab5/src_corpus/files/file_0.txt
/home/apo/ACE414_labs/lab5/src_corpus/files/file_1.txt
```

Every line of the 'file_logging.log' file is read through a loop. Each line is broken into substrings, called token. Each token contains information about the UID, Filename, Date, Time, Access_Type, Action_Denied flag and the Fingerprint. We care for the filename, date-time and access_type. \
The time and the date are stored as strings in two(2) buffers, with the format "DD-MM-YYYY" , "HH-MM-SS". Then, with the help of ```get_raw_dateTime(char* file_date, char* file_time)``` function, the substrings are convered back to epoch (raw) time format. This makes comparison to the current system time (obtained through ```time(NULL)```), much easier. The comparison is accomplished in the ```current_time_compare(time_t file_raw_tm)``` function.\
If the time of the log is within 20 minutes and the access_type is '0' (File creation), only then the filename is stored and the counter is incremented. Then the cycle repeats until all the logs are read. Each time, if the condition above is met, the filename is stored. The dublicates are ignored as the program checks if the filename that met the condition, is already stored. \
In the end, if the number of stored filenames is greater than the one specified by the user ('number_of_files' variable), the total amount of files created and their filenames are printed to the terminal.

<p>&nbsp;</p>

## <center>*Print encrypted files*</center>

```c
void print_encrypted_files(FILE *log);
```
This function prints all the files that were encrypted by the ransomware. It reads all the log entries and looks for filenames that contain the ".encrypt" suffix. The results are then reported to the user.

Example:
```
$ ./acmonitor -e
Files affected by ransomware: 2
Show their filenames? (y-n) y
/home/apo/ACE414_labs/lab5/src_corpus/files/file_0.txt.encrypt
/home/apo/ACE414_labs/lab5/src_corpus/files/file_1.txt.encrypt
```
Same as before. Every line of the 'file_logging.log' file is read through a loop. Each line is broken into substrings, called token. Each token contains information about the UID, Filename, Date, Time, Access_Type, Action_Denied flag and the Fingerprint. In this step, we only care for the filename and access_type. \
The filename and access_type are stored in the struct called 'entry' for later use. 
If the filename contains the suffix ".encrypt" and the access_type is '0' (File creation), only then the filename is stored and the counter is incremented. Then the cycle repeats until all the logs are read. Each time, if the condition above is met, the filename is stored. The dublicates are ignored as the program checks if the filename that met the condition, is already stored. \
In the end, the program prints the number of files with the ".encrypt" suffix, which are the files that where encrypted by the *ransomware*. The user is prompted with a message, for the filenames to be displayed. 

<p>&nbsp;</p>

## Utility Functions
We needed to construct some helper functions in order to get the time of the logs and compare it to the current time.

## <center>*Get raw Time and Date*</center>

```c
time_t get_raw_dateTime(char* file_date, char* file_time){
    /******************************
     * Time format = "00:40:13"
     * Date format = "13-12-2021"
     * ***************************/

    struct tm tm1;       

    // Print for debugging
    // printf("Date: %s, Time: %s\n", file_date, file_time);

    // Tokenize time string and store it in 'tm' struct
    tm1.tm_hour = atoi(strtok(file_time, ":"));
    tm1.tm_min = atoi(strtok(NULL, ":"));
    tm1.tm_sec = atoi(strtok(NULL, ":"));

    // Tokenize date string and store it in 'tm' struct
    tm1.tm_mday = atoi(strtok(file_date, "-"));
    tm1.tm_mon = atoi(strtok(NULL, "-")) - 1;
    tm1.tm_year = atoi(strtok(NULL, "-")) - 1900;
    tm1.tm_isdst = -1;

    // Return raw (epoch) time or '-1' on failure 
    return mktime(&tm1);
}
```
This function convert the date and time contained in the log files as strings with the format "DD-MM-YYYY" , "HH-MM-SS". These two(2) strings are tokenized and converted to strings and they are later passed to the fields of 'tm' struct. Then, using the ```mktime(&tm1)``` , the fields of the struct are converted back to Epoch (raw) time and returned by our function. 

## <center>*Compare current and log entry time*</center>

```c
int current_time_compare(time_t file_raw_tm){
    // File created the last 'minute_diff' minutes
    const int minute_diff = 20;

    // Get current time 
    time_t curr_time = time(NULL);

    // Error handling
    if(file_raw_tm == -1){
        fprintf(stderr, "Error with time, errno: \n%s!\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Check the age of the files
    if(curr_time - file_raw_tm <= minute_diff*60)
        return 1;
    return 0;
}
```
This function gets as input, the Epoch time of a log entry, and compares it to the current system time. The current time is obtained by calling the ```time(NULL)``` function. If the result of the subtraction of **log entry** and **current time** is less or equal than **20 minutes** (logs were created less than 20 minutes ago), the function returns '1', else returns '0'. 

*Epoch or Unix time, is the number of seconds that have elapsed since 1/1/1970.

<p>&nbsp;</p>

## License
<p style="color:red;">Apostolos Gioumertakis</p>