#include "utils.h"

/*
 * Prints the hex value of the input
 *
 * arg0: data
 * arg1: data len
 */
void
print_hex(long *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("%02X ", data[i]);
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 *
 * arg0: data
 * arg1: data len
 */
void
print_string(unsigned char *data, size_t len)
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


/*
 * Prints the usage message
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_3 -g \n" 
	    "    assign_3 -i in_file -o out_file -k key_file [-d | -e]\n" 
	    "    assign_3 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -k    path    Path to key file\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -g            Generates a keypair and saves to 2 files\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 * arg3: operation mode
 */
void
check_args(char *input_file, char *output_file, char *key_file, int op_mode)
{
	if ((!input_file) && (op_mode != 2)) {
		printf("Error: No input file!\n");
		usage();
	}

	if ((!output_file) && (op_mode != 2)) {
		printf("Error: No output file!\n");
		usage();
	}

	if ((!key_file) && (op_mode != 2)) {
		printf("Error: No user key!\n");
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


// My utils
int readFromFile(char * filename, void * data, int * len){
    FILE *fp;
   	fp = fopen(filename, "rb");
    if(fp == NULL){
        return 1;
    }
    /* File commands */ 
    /* (necessary for reading special characters like EOF, etc) */
    fseek(fp, 0, SEEK_END);     // go to file end
    *len = ftell(fp);           // calculate the file size
    rewind(fp);                 // go to file start and...
    if(fread(data, *len, sizeof(void), fp) == 0){
        fclose(fp);
        return 1;
    }
    fclose(fp);
    return 0;
}

int writeToFile(char * filename, void * data, int len){
    FILE *fp;
   	fp = fopen(filename, "wb");
    if(fp == NULL){
        return 1;
    }

    if(fwrite(data , sizeof(data[1]) , len , fp ) == 0){
		fclose(fp);
        return 1;
	}
    // fputs((const char*)data, fp);
    fclose(fp);
    return 0;
}

int appendToFile(char * filename, unsigned char * data, int len){
    FILE *fp;
   	fp = fopen(filename, "ab");
    if(fp == NULL){
        return 1;
    }

    if(fwrite(data , sizeof(unsigned char) , len , fp ) == 0){
		fclose(fp);
        return 1;
	}
    // fputs((const char*)data, fp);
    fclose(fp);
    return 0;
}

int writeKeyToFile(char * filename, size_t n, size_t eORd){
    FILE *fp;
   	fp = fopen(filename, "wb");
    if(fp == NULL){
        return 1;
    }

    if(fwrite(&n , sizeof(size_t) , 1 , fp ) == 0 || fwrite(&eORd , sizeof(size_t) , 1 , fp ) == 0){
		fclose(fp);
        return 1;
	}
    // fputs((const char*)data, fp);
    fclose(fp);
    return 0;
}

int readKeyFromFile(char * filename, size_t * n, size_t * eORd){
    FILE *fp;
   	fp = fopen(filename, "rb");
    if(fp == NULL){
        return 1;
    }

    if(fread(n , sizeof(size_t) , 1 , fp ) == 0 || fread(eORd , sizeof(size_t) , 1 , fp ) == 0){
		fclose(fp);
        return 1;
	}
    // fputs((const char*)data, fp);
    fclose(fp);
    return 0;
}
