#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Added libraries
#include <errno.h>
#include <openssl/md5.h>
#include <time.h>

#define MAXSIZE  0xFFFF

struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */

};

// Useful functions from Assignment 2
int readFromFile(FILE *fp, unsigned char * data, int * data_len){
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

// Date and time
struct tm * getDateTime(time_t t){
	struct tm* tm_ptr;
	// Convert it to local time and fill the struct
    tm_ptr = localtime(&t);
	// Convert using struct to human readable string
    // char * dateTime = asctime(tm_ptr);
    return tm_ptr;
}


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

/**
 * @brief A simple function to compare the time and date of the logs,
 *  with the current system time. If they are less than 20 minutes apart,
 *  '1'=true is returned. 
 * 
 * @param file_raw_tm The epoch (raw) time of the log entry
 * @return int '1' => less than 20 minutes 
 *              '0' => more than 20 minutes
 */
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

void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
           "-v <number of files>, Prints the total number of files created in the last 20 minutes\n"
           "-e, Prints all the files that were encrypted by the ransomware\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	char* data = (unsigned char*)malloc(sizeof(char)*256);
	size_t data_len = 0;
	// if(readFromFile(log, data, (int*)&data_len) == 1){
    //     fprintf(stderr, "Error reading from file, errno: \n%s!\n", strerror(errno));
    //     exit(EXIT_FAILURE);
    // }
	
	struct entry *logs = (struct entry *)malloc(sizeof(struct entry)*MAXSIZE);
	// if(getline(&data, &data_len, log) == 0){
	// 	fprintf(stderr, "Error!!! %s.\n", strerror(errno));
    //     exit(EXIT_FAILURE);
	// }
    int i = 0;
    int res = 0;

    int * uids = (int*)malloc(sizeof(int) * 100);
    int uids_len = 0;
    int uid_exists = 0;

	// Discard first line
    if((res = getline(&data, &data_len, log)) == -1) return; 

    // Read logs from file line-by-line and store the in struct array
    while ((res = getline(&data, &data_len, log)) != -1) 
    {
        logs[i].file = (char*)malloc(sizeof(char)*100);        
        logs[i].fingerprint = (char*)malloc(sizeof(char)*MD5_DIGEST_LENGTH*2);        
        char* date;// = (unsigned char*)malloc(sizeof(char)*15);
        char* time;// = (unsigned char*)malloc(sizeof(char)*15);
        logs[i].uid = atoi(strtok(data, "|"));
        strcpy(logs[i].file, strtok(NULL, "|"));  
        date = strtok(NULL, "|");
        time = strtok(NULL, "|");
        logs[i].access_type = atoi(strtok(NULL, "|"));
        logs[i].action_denied = atoi(strtok(NULL, "|"));
        strcpy(logs[i].fingerprint, strtok(NULL, "|"));

            // Find unique UIDs
        // If the list is empty...
        if(uids_len == 0){
            // ... add a uid
            uids[uids_len] = logs[i].uid;
            /// And increase the size
            uids_len++;
        }
        // If it's not empty....
        else {
            // ....compare the uid[i] to the uids in the list
            int j;
            for(j=0; j<uids_len; j++){
                if(uids[j] == logs[i].uid){
                    uid_exists = 1;
                    break;
                }
            }
            // If the uid is unique (not present in the list)...
            if(uid_exists != 1){
                // ...add the uid
                uids[uids_len] = logs[i].uid;
                // Increase list size
                uids_len++;
            }
            // Restore value for next iteration
            uid_exists = 0;
        }
        
        i++;
    }

    // Get the size of the struct array
    int logs_len = i;

    // Print all uids for debugging
    // printf("UIDs length: %d\n", uids_len);
    // for (i = 0; i < uids_len; i++)
    // {
    //     printf("UID %d: %d\n", i, *(uids+i));
    // }
        
    // Create an array for unique files (lets call it 'list')
    char ** items = (char**)malloc(sizeof(char*) * logs_len);
    
    // The size of that array
    int items_len = 0;

    // If a files has multiple accesses from one user --> 1
    int exists = 0;

	// Just to print a message if no malicious uid exists
	int malicious = 0;

    for(int k=0; k<uids_len; k++){

        // Iterate for every file in the logs
        for (i = 0; i < logs_len; i++) {

            // We care for one user at a time and only if he/she has no rights
            if(logs[i].uid == uids[k] && logs[i].action_denied == 1){
                // If the list is empty...
                if(items_len == 0){
                    // ... add a file
                    items[items_len] = logs[i].file;
                    /// And increase the size
                    items_len++;
                }
                // If it's not empty....
                else {
                    // ....compare the file[i] to the files in the list
                    for(int j=0; j<items_len; j++){
                        exists |= (strcmp(items[j], logs[i].file) == 0);
                    }
                    // If the file is unique (not present in the list)...
                    if(exists != 1){
                        // ...add the file
                        items[items_len] = logs[i].file;
                        // Increase list size
                        items_len++;
                    }
                    // Restore value for next iteration
                    exists = 0;
                }
            }
        }
		// User accessed more than 7 files without auth
        if(items_len >= 7){
            printf("Malicious UID: %d\t", uids[k]);
            // Print all files for each uid (for debugging)
            printf("Accessed Files: %d\n", items_len);
            // for (i = 0; i < items_len; i++)
            // {
            //     printf("File%d: %s\n", i, *(items+i));
            // }
			malicious |= 1;
        }

        // Restore the list size
        items_len = 0;
    }
	if(!malicious)
		printf("No malicious UID found\n");

    free(data);
    free(logs);
    free(uids);
    free(items);
	return;

}


void
list_file_modifications(FILE *log, char *file_to_scan)
{
    char* data = (unsigned char*)malloc(sizeof(char)*256);
	size_t data_len = 0;
	
	struct entry *logs = (struct entry *)malloc(sizeof(struct entry)*MAXSIZE);

    int i = 0;
    int res = 0;

    int * uids = (int*)malloc(sizeof(int) * 100);
    int uids_len = 0;
    int uid_exists = 0;

	// Discard first line
    if((res = getline(&data, &data_len, log)) == -1) return; 

    // Read logs from file line-by-line and store the in struct array
    while ((res = getline(&data, &data_len, log)) != -1) 
    {
        logs[i].file = (char*)malloc(sizeof(char)*100);        
        logs[i].fingerprint = (char*)malloc(sizeof(char)*MD5_DIGEST_LENGTH*2);        
        char* date;// = (unsigned char*)malloc(sizeof(char)*15);
        char* time;// = (unsigned char*)malloc(sizeof(char)*15);
        logs[i].uid = atoi(strtok(data, "|"));
        strcpy(logs[i].file, strtok(NULL, "|"));  
        date = strtok(NULL, "|");
        time = strtok(NULL, "|");
        logs[i].access_type = atoi(strtok(NULL, "|"));
        logs[i].action_denied = atoi(strtok(NULL, "|"));
        strcpy(logs[i].fingerprint, strtok(NULL, "|"));

            // Find unique UIDs
        if(strcmp(logs[i].file, file_to_scan) == 0){
        
            // If the list is empty...
            if(uids_len == 0){
                // ... add a uid
                uids[uids_len] = logs[i].uid;
                /// And increase the size
                uids_len++;
            }
            // If it's not empty....
            else {
                // ....compare the uid[i] to the uids in the list
                int j;
                for(j=0; j<uids_len; j++){
                    if(uids[j] == logs[i].uid){
                        uid_exists = 1;
                        break;
                    }
                }
                // If the uid is unique (not present in the list)...
                if(uid_exists != 1){
                    // ...add the uid
                    uids[uids_len] = logs[i].uid;
                    // Increase list size
                    uids_len++;
                }
                // Restore value for next iteration
                uid_exists = 0;
            }
        }
        i++;
    }

    // Get the size of the struct array
    int logs_len = i;

    // // Print every log (for debugging)
    // for(int j=0; j<i; j++){
    //     printf("\tLog entry: %d\n", j+1);
    //     printf("UID: %d\n", logs[j].uid);
    //     printf("File name: %s\n", logs[j].file);
    //     // printf("Date: %s\n", date);
    //     // printf("Timestamp: %s\n", time);
    //     printf("Access Type: %d\n", logs[j].access_type);
    //     printf("Action denied flag: %d\n", logs[j].action_denied);
    //     printf("Fingerprint(MD5): %s\n", logs[j].fingerprint);
    //     // print_hex((unsigned char*)logs[j].fingerprint, MD5_DIGEST_LENGTH);
    //     // print_string((unsigned char*)logs[j].fingerprint, MD5_DIGEST_LENGTH);
    //     printf("\n\n"); 
    // }


    // Print all uids for debugging
    // printf("UIDs length: %d\n", uids_len);
    // for (i = 0; i < uids_len; i++)
    // {
    //     printf("UID %d: %d\n", i, *(uids+i));
    // }
    

    char * prev_hash;

    // The size of that array
    int hashes_len = 0;

    // If a files has multiple accesses from one user --> 1
    int exists = 0;

    for(int k=0; k<uids_len; k++){
		for (i = 0; i < logs_len; i++) {
			if(logs[i].uid == uids[k] && strcmp(logs[i].file , file_to_scan) == 0){
				prev_hash = logs[i].fingerprint;
				break;
			}
		}
        // Iterate for every file in the logs
        for (i = 0; i < logs_len; i++) {

            // We care for one user at a time and only for a specific file
            if(logs[i].uid == uids[k] && strcmp(logs[i].file , file_to_scan) == 0){
				// printf("%s Vs %s\n", prev_hash, logs[i].fingerprint);
				if(strcmp(prev_hash, logs[i].fingerprint) != 0){
					hashes_len++;
				}
				prev_hash = logs[i].fingerprint;
            }
        }
        printf("File: %s\n", file_to_scan);
        
        printf("UID: %d", uids[k]);
        printf("\tTimes modified: %d\n", hashes_len);
        

        // Restore the list size
        hashes_len = 0;

    }
	free(data);
    free(logs);
    free(uids);
	return;

}

void
list_tot_number_of_files_20min(FILE *log, int number_of_files){

    // To temporarily store the entries from the log file
    char* data = (unsigned char*)malloc(sizeof(char)*256);
	// Size of that data
    size_t data_len = 0;
	
    // An array of structs to store each entry (up to 65535 logs)
	struct entry *logs = (struct entry *)malloc(sizeof(struct entry)*MAXSIZE);

    int i = 0;
    int res = 0;

    // Create an array for unique files (lets call it 'list')
    char ** items = (char**)malloc(sizeof(char*) * MAXSIZE);
    // The size of that array
    int items_len = 0;
    // The file exists more than once
    int exists = 0;

	// Discard first line
    if((res = getline(&data, &data_len, log)) == -1) return; 

    // Allocate memory for date and time strings
    char* date = (unsigned char*)malloc(sizeof(char)*20);
    char* time = (unsigned char*)malloc(sizeof(char)*20);

    // Read logs from file line-by-line and store the in struct array
    while ((res = getline(&data, &data_len, log)) != -1) 
    {
        logs[i].file = (char*)malloc(sizeof(char)*100);        
        logs[i].fingerprint = (char*)malloc(sizeof(char)*MD5_DIGEST_LENGTH*2);        
        logs[i].uid = atoi(strtok(data, "|"));
        strcpy(logs[i].file, strtok(NULL, "|"));  
        strcpy(date, strtok(NULL, "|"));
        strcpy(time, strtok(NULL, "|"));
        logs[i].access_type = atoi(strtok(NULL, "|"));
        logs[i].action_denied = atoi(strtok(NULL, "|"));
        strcpy(logs[i].fingerprint, strtok(NULL, "|"));

        // Unformat date and time for easier comparison
        logs[i].time = get_raw_dateTime(date, time);        


        // Find unique files
        // We care for files created less than 20 minutes ago....
        // ... created meaning access_type=0
        if(current_time_compare(logs[i].time) == 1 && logs[i].access_type == 0){
            // If the list is empty...
            if(items_len == 0){
                // ... add a file
                items[items_len] = logs[i].file;
                /// And increase the size
                items_len++;
            }
            // If it's not empty....
            else {
                // ....compare the file[i] to the files in the list
                for(int j=0; j<items_len; j++){
                    exists |= (strcmp(items[j], logs[i].file) == 0);
                }
                // If the file is unique (not present in the list)...
                if(exists != 1){
                    // ...add the file
                    items[items_len] = logs[i].file;
                    // Increase list size
                    items_len++;
                }
                // Restore value for next iteration
                exists = 0;
            }
        }
        
        i++;

    }

    // Get the size of the struct array
    int logs_len = i;

    if(items_len >= number_of_files){
        printf("Files created less than 20 minutes ago: %d\n", items_len);
        for (i = 0; i < items_len; i++) {
            printf("%s\n", items[i]);
        }
    }
    else{
        printf("Found less than %d files\n", number_of_files);
    }
    
    free(data);
    free(logs);
    free(items);
    free(date);
    free(time);
    
}

void
print_encrypted_files(FILE *log){
    // To temporarily store the entries from the log file
    char* data = (unsigned char*)malloc(sizeof(char)*256);
	// Size of that data
    size_t data_len = 0;
	
    // An array of structs to store each entry (up to 65535 logs)
	struct entry *logs = (struct entry *)malloc(sizeof(struct entry)*MAXSIZE);

    int i = 0;
    int res = 0;

    // Create an array for unique files (lets call it 'list')
    char ** items = (char**)malloc(sizeof(char*) * MAXSIZE);
    // The size of that array
    int items_len = 0;
    // The file exists more than once
    int exists = 0;

	// Discard first line
    if((res = getline(&data, &data_len, log)) == -1) return; 

    // Allocate memory for date and time strings
    char* date = (unsigned char*)malloc(sizeof(char)*20);
    char* time = (unsigned char*)malloc(sizeof(char)*20);

    // Read logs from file line-by-line and store the in struct array
    while ((res = getline(&data, &data_len, log)) != -1) 
    {
        logs[i].file = (char*)malloc(sizeof(char)*100);        
        logs[i].fingerprint = (char*)malloc(sizeof(char)*MD5_DIGEST_LENGTH*2);        
        logs[i].uid = atoi(strtok(data, "|"));
        strcpy(logs[i].file, strtok(NULL, "|"));  
        strcpy(date, strtok(NULL, "|"));
        strcpy(time, strtok(NULL, "|"));
        logs[i].access_type = atoi(strtok(NULL, "|"));
        logs[i].action_denied = atoi(strtok(NULL, "|"));
        strcpy(logs[i].fingerprint, strtok(NULL, "|"));

        // Unformat date and time for easier comparison
        logs[i].time = get_raw_dateTime(date, time);        


        // Find unique files
        // We care for files containing the ".encrypt" substring....
        // ... created meaning access_type=0
        if(strstr(logs[i].file, ".encrypt") != NULL && logs[i].access_type == 0){
            // If the list is empty...
            if(items_len == 0){
                // ... add a file
                items[items_len] = logs[i].file;
                /// And increase the size
                items_len++;
            }
            // If it's not empty....
            else {
                // ....compare the file[i] to the files in the list
                for(int j=0; j<items_len; j++){
                    exists |= (strcmp(items[j], logs[i].file) == 0);
                }
                // If the file is unique (not present in the list)...
                if(exists != 1){
                    // ...add the file
                    items[items_len] = logs[i].file;
                    // Increase list size
                    items_len++;
                }
                // Restore value for next iteration
                exists = 0;
            }
        }
        
        i++;

    }

    // Get the size of the struct array
    int logs_len = i;

    printf("Files affected by ransomware: %d\n", items_len);
    for (i = 0; i < items_len; i++) {
        printf("%s\n", items[i]);
    }
    
    free(data);
    free(logs);
    free(items);
    free(date);
    free(time);
    
}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "i:v:hem")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
        case 'v':
            list_tot_number_of_files_20min(log, atoi(optarg));
            break;
        case 'e':
            print_encrypted_files(log);
            break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
