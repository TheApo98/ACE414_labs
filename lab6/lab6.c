#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

#include <netinet/in.h>
#include <net/ethernet.h>

int packet_count = 0;
int tcp_packet_count = 0;
int udp_packet_count = 0;

void print_hex(unsigned char *data, size_t len);
void print_string(unsigned char *data, size_t len);
void print_ip(const u_char *data);

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

// void print_packet_info(const u_char *packet, struct pcap_pkthdr packet_header) {
//     printf("Packet capture length: %d\n", packet_header.caplen);
//     printf("Packet total length %d\n", packet_header.len);
// }

void tcp_packet_info(const u_char *packet, u_int32_t cap_packet_len, int ip_header_length){
    // Header pointers
    const u_char *tcp_header;
    const u_char *payload;
    
    // Header lengths
    int ethernet_header_length = 14; /* Doesn't change */
    int payload_length;
    int tcp_header_length;

    // Point to the start of the TCP header
    tcp_header = packet + ethernet_header_length + ip_header_length;
    // first half of 13th byte is the header length... 
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    // ...multiplied by 4
    tcp_header_length = tcp_header_length * 4;
    printf("TCP header length in bytes: %d\n", tcp_header_length);

    // Find source and dest ports 
    const u_char * source_port = tcp_header; 
    const u_char * dest_port = tcp_header + 2; 
    int src_port = (*source_port << 8) | (*(source_port + 1)); 
    int dst_port = (*dest_port << 8) | (*(dest_port + 1)); 
    printf("Source port: %d\n", src_port);
    printf("Destination port: %d\n", dst_port);

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
    printf("Size of all headers combined: %d bytes\n", total_headers_size);
    payload_length = cap_packet_len - total_headers_size;
    printf("Payload size: %d bytes\n", payload_length);
    payload = packet + total_headers_size;
    // printf("Memory address where payload begins: %p\n\n", payload);

    /* Print payload in ASCII */
    /*  
    if (payload_length > 0) {
        const u_char *temp_pointer = payload;
        int byte_count = 0;
        while (byte_count++ < payload_length) {
            printf("%c", *temp_pointer);
            temp_pointer++;
        }
        printf("\n");
    }
    */
}

// Callback routine called by pcap_loop()
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    printf("Packet: %d\n", packet_count++);

    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    printf("Total packet available: %d bytes\n", header->caplen);
    printf("Expected packet size: %d bytes\n", header->len);

    /* Pointers to start point of various headers */
    const u_char *ip_header;

    /* Header lengths in bytes */
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length;

    /* Find start of IP header */
    ip_header = packet + ethernet_header_length;
    // second half of 1st byte is the header length.... 
    ip_header_length = ((*ip_header) & 0x0F);
    // ...multiplied by 4
    ip_header_length = ip_header_length * 4;
    printf("IP header length (IHL) in bytes: %d\n", ip_header_length);

    // Find source and dest ip addresses 
    const u_char * source_ip = ip_header + ip_header_length - 4*2; 
    const u_char * dest_ip = ip_header + ip_header_length - 4; 
    printf("Source ip: ");
    print_ip(source_ip);
    printf("Destination ip: ");
    print_ip(dest_ip);


    u_char protocol = *(ip_header + 9);
    if (protocol == IPPROTO_TCP) {
        tcp_packet_count++;
        tcp_packet_info(packet, header->caplen, ip_header_length);
        // printf("Not a TCP packet. Skipping...\n\n");
    }
    else if (protocol == IPPROTO_UDP) {
        udp_packet_count++;
        // tcp_packet_info(packet, header->caplen, ip_header_length);
        // printf("Not a TCP packet. Skipping...\n\n");
    }

    printf("\n");
    

    return;
}

int pcap_file_read(char * filename){
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, error_buffer);
    
    if (handle == NULL) {
        printf("Error opening file: %s\n", error_buffer);
        return 1;
    }

    pcap_loop(handle, 0, my_packet_handler, NULL);

    printf("Total packets: %d\n", packet_count);
    printf("Total TCP packets: %d\n", tcp_packet_count);
    printf("Total UDP packets: %d\n", udp_packet_count);
    return 0;
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
            // printf("Filename: %s\n", optarg);
            pcap_file_read(optarg);
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

/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
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


/*
 * Prints the input as string
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

void
print_ip(const u_char *data)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
        // ip length is 4 bytes
		for (i = 0; i < 3; i++)
			printf("%d.", data[i]);
        printf("%d", data[3]);
		printf("\n");
	}
}