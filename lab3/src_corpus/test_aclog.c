#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <errno.h>
#include <stdlib.h>       
#include <unistd.h>


int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};


	/* example source code */

	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}
	
	struct stat stats;
	printf("Cur UID: %d\n", getuid());
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





}
