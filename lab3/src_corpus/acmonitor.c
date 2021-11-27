#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Added libraries
#include <errno.h>
#include <openssl/md5.h>

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
	
	struct entry *logs = (struct entry *)malloc(sizeof(struct entry)*1000);
	// if(getline(&data, &data_len, log) == 0){
	// 	fprintf(stderr, "Error!!! %s.\n", strerror(errno));
    //     exit(EXIT_FAILURE);
	// }
    int i = 0;
    int res = 0;

    int * uids = (int*)malloc(sizeof(int) * 100);
    int uids_len = 0;
    int uid_exists = 0;

    // Read logs from file line-by-line and store the in struct array
    while ((res = getline(&data, &data_len, log)) != -1) 
    {
        logs[i].file = (char*)malloc(sizeof(char)*100);        
        logs[i].fingerprint = (char*)malloc(sizeof(char)*MD5_DIGEST_LENGTH);        
        // printf("Res: %d, i: %d\n", res, i);
        char* date;// = (unsigned char*)malloc(sizeof(char)*15);
        char* time;// = (unsigned char*)malloc(sizeof(char)*15);
        // printf("%s\n", data);
        logs[i].uid = atoi(strtok(data, "|"));
        // printf("Tmp: %s\n", tmp);
        strcpy(logs[i].file, strtok(NULL, "|"));  
        date = strtok(NULL, "|");
        time = strtok(NULL, "|");
        // printf("Date: %s, time: %s\n", date, time);
        logs[i].access_type = atoi(strtok(NULL, "|"));
        logs[i].action_denied = atoi(strtok(NULL, "|"));
        // fread(logs[i].fingerprint, sizeof(char), MD5_DIGEST_LENGTH, log);
        // printf("data: %s\n", data);
        memcpy(logs[i].fingerprint, strtok(NULL, "\n"), MD5_DIGEST_LENGTH);
        // print_hex(logs[i].fingerprint, MD5_DIGEST_LENGTH);

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
    printf("UIDs length: %d\n", uids_len);

    // Get the size of the struct array
    int logs_len = i;

    // // Print every log (for debugging)
    // for(int j=0; j<i; j++){
    //     printf("\tLog entry: %d\n", j);
    //     printf("UID: %d\n", logs[j].uid);
    //     printf("File name: %s\n", logs[j].file);
    //     // printf("Date: %s\n", date);
    //     // printf("Timestamp: %s\n", time);
    //     printf("Access Type: %d\n", logs[j].access_type);
    //     printf("Action denied flag: %d\n", logs[j].action_denied);
    //     printf("Fingerprint(MD5): ");
    //     print_hex((unsigned char*)logs[j].fingerprint, MD5_DIGEST_LENGTH);
    //     // print_string((unsigned char*)logs[j].fingerprint, MD5_DIGEST_LENGTH);
    //     printf("\n\n"); 
    // }

    // Print all uids for debugging
    for (i = 0; i < uids_len; i++)
    {
        printf("UID %d: %d\n", i, *(uids+i));
    }
        
    // Create an array for unique files (lets call it 'list')
    char ** items = (char**)malloc(sizeof(char*) * logs_len);
    
    // The size of that array
    int items_len = 0;

    // If a files has multiple accesses from one user --> 1
    int exists = 0;

    for(int k=0; k<uids_len; k++){

        // Iterate for every file in the logs
        for (i = 0; i < logs_len; i++) {

            // We care for one user at a time and only if he/she has no rights
            if(logs[i].uid == uids[k] && logs[i].action_denied == 1){
                // printf("UID: %d ", logs[i].uid);
                // printf("File: %s\n", logs[i].file);
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
        if(items_len >= 7){
            printf("Malicious UID: %d\n", uids[k]);
            // Print all files for each uid (for debugging)
            printf("Diff files: %d\n", items_len);
            for (i = 0; i < items_len; i++)
            {
                printf("File%d: %s\n", i, *(items+i));
            }
        }

        // Restore the list size
        items_len = 0;
        // Erase the list
        // free(items);

    }

    free(data);
    free(logs);
    free(uids);
    free(items);
	return;

}


void
list_file_modifications(FILE *log, char *file_to_scan)
{

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */

	return;

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

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
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
