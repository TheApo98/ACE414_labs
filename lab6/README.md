# Assignment_6: Monitoring the network traffic using the Packet Capture library
You are expected to read a pcap file (test_pcap_5mins.pcap ), and you will process the incoming/outcoming TCP and UDP packets



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
make
```

To run the **Network Monitoring** tool, use the following command:

```bash
./acmonitor
```

## Usage

Help menu of the *Network Monitor*:
```
$ ./monitor 

usage:
        ./monitor 
Options:
-r <filename>, Packet capture file name
-h, Help message
```


<p>&nbsp;</p>

## 1) Pcap file open and read
Using the ```pcap_open_offline(filename, error_buffer)``` function , we can open the pcap file for processing. With the help of the ```pcap_loop(handle, 0, my_packet_handler, NULL)``` function, we can read the packets inside the pcap file. The first argument is the "pcap_t * handle" , i.e. the pcap file, the second the number of loops the function performs, '0' means till EOF, and the  third is the callback routine that is called every time.


<p>&nbsp;</p>


## 2) Callback routine
```c
void my_packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
```
This function extracts information about a packet from the pcap file, every time it is called. First, the packet counter is incremented, regardless of the packet type (Needed for statistics). The packet must be an IP packet (we don't care about ARP and other packets). General information about the packet, such as the total length, is stored in the packet at first and the more specialized information is gathered with the help of ```ip_packet_info()``` and ```tcp_packet_info()``` or ```udp_packet_info()``` for TCP and UDP packets respectively. \
If the payload length is '0', then the packet is considered as a network flow. A new ```network_flow``` struct is created and inserted in the list of network flows. \
In the end, gathered information about the packet is printed through ```print_packet_info()```. 



## <center>*ip_packet_info() function*</center>

```c
void ip_packet_info(const u_char *packet, struct packet *p);
```
In this function the ip header length is calculated as well as the **source** and **destination** IPs of the packet. Also, the protocol of the packet. \
We have to calculate the position of the IP header in the packet, which is after the Ethernet header. The Ethernet header length is known (14 bytes), so the position can be easily found. The length of the IP header is the second half of 1st byte (after the start of the IP header), multiplied by 4. \
The source and destination IP are the last 8 bytes of the IP header (4 bytes each).\
The protocol is 10th byte after the start of the IP header. \
All the information mentioned above is stored in the packet struct.



## <center>*tcp_packet_info() function*</center>
```c
void tcp_packet_info(const u_char *packet, struct packet *p);
```
In this function, the TCP header and payload length is calculated, as well as the source and destination ports. Again, we have to calculate the position of the TCP header, which is after the IP header. Knowing the IP header length, we can easily find the start of the TCP header. The length of the TCP header is first half of 13th byte is the header length, multiplied by 4. \
Conveniently, the source and destination ports are the first 4 bytes after the start of the header. To convert them from bytes to integers, the first byte is shifted left 8 bits and OR-ed with the second byte. Knowing all the total length and the lengths of all headers, we can easily calculate the payload length. \
The information mentioned above is again stored in the packet struct.

## <center>*udp_packet_info() function*</center>
```c
void tcp_packet_info(const u_char *packet, struct packet *p);
```
In this function, the UDP header and payload length is calculated, as well as the source and destination ports. Again, we have to calculate the position of the UDP header, which is after the IP header. Knowing the IP header length, we can easily find the start of the UDP header. The length of the UDP header is 8 bytes by default. The total UDP length (header and payload) is the 5th and 6th byte after the start of the header. \
Again, the source and destination ports are the first 4 bytes after the start of the header. To convert them from bytes to integers, the first byte is shifted left 8 bits and OR-ed with the second byte. Knowing all the total packet length and the lengths of all headers, we can easily calculate the payload length. \
The information mentioned above is again stored in the packet struct.
 
<p>&nbsp;</p>

<p>&nbsp;</p>

## License
<p style="color:red;">Apostolos Gioumertakis</p>