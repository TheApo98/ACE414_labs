#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./lab6 \n"
		   "Options:\n"
		   "-r <filename>, Packet capture file name\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}

int 
main(int argc, char *argv[])
{

	int ch;

	if (argc < 2)
		usage();

	while ((ch = getopt(argc, argv, "r:h")) != -1) {
		switch (ch) {		
		case 'r':
            printf("Filename: %s\n", optarg);
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


	argc -= optind;
	argv += optind;	
	
	return 0;
}