#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>       
#include <unistd.h>


int main(int argc, char *argv[]) 
{
	int i;
	size_t bytes;
	FILE *file;

	/* A simple program to create X amount of files */
	/* Usage: ./test_aclog <number_of_files> <directory> <filename_format> */  

	// Reserve space for strings
	char *filename = (char*)malloc(sizeof(char)*256);
	char *directory = (char*)malloc(sizeof(char)*256);
	char *filename_format = (char*)malloc(sizeof(char)*256);

	int number_of_files = atoi(argv[1]);
	strcpy(directory, argv[2]);
	strcpy(filename_format, argv[3]);

	for (i = 0; i < number_of_files; i++)
	{
		// pass the path to the filename variable
		sprintf(filename, "%s/%s%d.txt", directory, filename_format, i);
		// printf("File: %s\n", filename);
		file = fopen(filename, "w");
		if (file == NULL) {
			printf("fopen error\n");
			printf("%s!\n\n", strerror(errno));
		}
		else {
			// Add the path as content in the file
			bytes = fwrite(filename, 1, strlen(filename), file);
			fclose(file);
		}
	}

}
