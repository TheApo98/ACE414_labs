#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>

#include <netinet/in.h>
#include <net/ethernet.h>

u_int packet_count = 0;
u_int tcp_packet_count = 0;
u_int udp_packet_count = 0;
u_int tcp_packet_bytes = 0;
u_int udp_packet_bytes = 0;

struct packet
{
    int packet_no;
    u_char * source_ip;
    u_char * dest_ip;

    uint16_t src_port;
    uint16_t dst_port;

    uint8_t protocol;

    int total_len;
    int ip_header_len;    
    int tcpUdp_header_len;    
    int payload_len;

    int is_retransmitted;
};

struct network_flow
{
    u_char * source_ip;
    u_char * dest_ip;

    uint16_t src_port;
    uint16_t dst_port;

    uint8_t protocol;
    struct network_flow * next;
};

void print_hex(unsigned char *data, size_t len);
void print_string(unsigned char *data, size_t len);
void print_ip(const u_char *data);
struct network_flow * new_net_flow(struct network_flow *head, struct packet *p);
struct network_flow * add_net_flow(struct network_flow *head, struct network_flow *node);
int net_flow_exists(struct network_flow *head, struct network_flow *node);


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

void print_packet_info(struct packet *p) {
    printf("Packet no: %d\n", p->packet_no);
    printf("Packet total captured length %d\n", p->total_len);
    printf("IP header length in bytes: %d\n", p->ip_header_len);

    printf("Source ip: ");
    print_ip(p->source_ip);
    printf("Destination ip: ");
    print_ip(p->dest_ip);

    if(p->protocol == IPPROTO_TCP)
        printf("TCP header length in bytes: %d\n", p->tcpUdp_header_len);
    else
        printf("UDP header length in bytes: %d\n", p->tcpUdp_header_len);

    printf("Source port: %d\n", p->src_port);
    printf("Destination port: %d\n", p->dst_port);
    printf("Payload length in bytes: %d\n", p->payload_len);

    printf("Is retransmission? ");
    p->is_retransmitted ? printf("Yes\n") : printf("No\n");

    printf("\n");

}

void ip_packet_info(const u_char *packet, struct packet *p){

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
    // store to struct
    p->ip_header_len = ip_header_length;

    // Find source and dest ip addresses manualy
    const u_char * source_ip = ip_header + ip_header_length - 4*2; 
    const u_char * dest_ip = ip_header + ip_header_length - 4; 
    p->source_ip = strdup(source_ip);
    p->dest_ip = strdup(dest_ip);

    // Store the protocol
    p->protocol = *(ip_header + 9);
}

void tcp_packet_info(const u_char *packet, struct packet *p){
    // Header pointers
    const u_char *tcp_header;
    const u_char *payload;
    
    // Header lengths
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length = p->ip_header_len;
    int tcp_header_length;
    int payload_length;

    int cap_packet_len = p->total_len;

    // Point to the start of the TCP header
    tcp_header = packet + ethernet_header_length + ip_header_length;
    // first half of 13th byte is the header length... 
    tcp_header_length = ((*(tcp_header + 12)) & 0xF0) >> 4;
    // ...multiplied by 4
    tcp_header_length = tcp_header_length * 4;
    p->tcpUdp_header_len = tcp_header_length;

    // Find source and dest ports 
    const u_char * source_port = tcp_header; 
    const u_char * dest_port = tcp_header + 2; 
    uint16_t src_port = (*source_port << 8) | (*(source_port + 1)); 
    uint16_t dst_port = (*dest_port << 8) | (*(dest_port + 1)); 
    p->src_port = src_port;
    p->dst_port = dst_port;

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length + ip_header_length + tcp_header_length;
    payload_length = cap_packet_len - total_headers_size;
    p->payload_len = payload_length;
    // payload pointer
    payload = packet + total_headers_size;

}

void udp_packet_info(const u_char *packet, struct packet *p){
    // Header pointers
    const u_char *udp_header;
    const u_char *payload;
    
    // Header lengths
    int ethernet_header_length = 14; /* Doesn't change */
    int ip_header_length = p->ip_header_len;
    int udp_header_length = 8;      /* Doesn't change */
    int udp_total_length;
    int payload_length;

    // The total captured packet length
    int cap_packet_len = p->total_len;

    // Point to the start of the TCP header
    udp_header = packet + ethernet_header_length + ip_header_length;
    // the 5th-8th bytes are the UDP total length (header + payload)
    const u_char * udp_len_pointer = udp_header + 4;
    udp_total_length = (*udp_len_pointer << 8) | (*(udp_len_pointer + 1));
    // Store udp header length
    p->tcpUdp_header_len = udp_header_length;
    // printf("UDP header length in bytes: %d\n", udp_header_length);

    // Find source and dest ports 
    const u_char * source_port = udp_header; 
    const u_char * dest_port = udp_header + 2; 
    uint16_t src_port = (*source_port << 8) | (*(source_port + 1)); 
    uint16_t dst_port = (*dest_port << 8) | (*(dest_port + 1)); 
    p->src_port = src_port;
    p->dst_port = dst_port;

    /* Add up all the header sizes to find the payload offset */
    int total_headers_size = ethernet_header_length + ip_header_length + udp_header_length;
    payload_length = cap_packet_len - total_headers_size;
    // Store payload length
    p->payload_len = payload_length;
    // payload pointer
    payload = packet + total_headers_size;

}

// Callback routine called by pcap_loop()
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    // Increment counter
    packet_count++;

    // Allocate space for packet struct
    struct packet * pac = (struct packet*)malloc(sizeof(struct packet));

    /* First, lets make sure we have an IP packet */
    struct ether_header *eth_header;
    eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
        printf("Not an IP packet. Skipping...\n\n");
        return;
    }

    // Number of the packet in the file
    pac->packet_no = packet_count;
    // Store lenght of captured packet
    pac->total_len = header->caplen;

    ip_packet_info(packet, pac);

    // Check the protocol
    u_char protocol = pac->protocol;
    if (protocol == IPPROTO_TCP) {
        tcp_packet_count++;
        tcp_packet_bytes+=header->caplen;
        tcp_packet_info(packet, pac);
    }
    else if (protocol == IPPROTO_UDP) {
        udp_packet_count++;
        udp_packet_bytes+=header->caplen;
        udp_packet_info(packet, pac);
    }

    print_packet_info(pac);
    
    // Free packet memory
    free(pac->source_ip);
    free(pac->dest_ip);
    free(pac);

    return;
}

int pcap_file_read(char * filename){
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(filename, error_buffer);
    
    if (handle == NULL) {
        printf("Error opening file: %s\n", error_buffer);
        return 1;
    }

    if(pcap_loop(handle, 0, my_packet_handler, NULL) < 0)
        printf("Error\n");

    printf("**** Stats ****\n");
    printf("Total packets: %d\n", packet_count);
    printf("Total TCP packets: %d\n", tcp_packet_count);
    printf("Total UDP packets: %d\n", udp_packet_count);
    printf("Total bytes of TCP packets: %d\n", tcp_packet_bytes);
    printf("Total bytes of UDP packets: %d\n", udp_packet_bytes);
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

/* Lists */

struct network_flow * new_net_flow(struct network_flow *head, struct packet *p)
{
    struct network_flow * flow = (struct network_flow *)malloc(sizeof(struct network_flow));

    flow->source_ip = strdup(p->source_ip);
    flow->dest_ip = strdup(p->dest_ip);
    flow->src_port = p->src_port;
    flow->dst_port = p->dst_port;
    flow->protocol = p->protocol;
    flow->next = NULL;

    return flow;
}

struct network_flow * add_net_flow(struct network_flow *head, struct network_flow *node)
{
    if(head == NULL){
        return node;
    }

    // Temp node for traversing
    struct network_flow *cur = head;

    // Move the temp node till the end of the list
    while(cur->next != NULL){
        cur = cur->next;
    }

    // Add the new node at the end
    cur->next = node;

    // Return the head of the list
    return head;
}

int net_flow_exists(struct network_flow *head, struct network_flow *node)
{
    // Temp node for traversing
    struct network_flow *cur = head;

    // Move the temp node till the end of the list
    while(cur != NULL){
        if(strcmp(cur->source_ip, node->source_ip) == 0 && strcmp(cur->dest_ip, node->dest_ip) == 0 && cur->src_port == node->src_port && cur->dst_port == node->dst_port && cur->protocol == node->protocol){
            return 1;
        }
        cur = cur->next;
    }

    return 0;
}


/* Utilities */


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