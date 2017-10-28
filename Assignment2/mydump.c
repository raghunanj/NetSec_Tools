#include <stdio.h>
#include <pcap.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <string.h>
#include <stdlib.h>

#include <unistd.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>



/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; /* IP? ARP? RARP? etc */
 	const struct ether_addr eth_src[6], eth_dst[6];
};

/* IP header */
struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
	u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
	u_short th_win;		/* window */
	u_short th_sum;		/* checksum */
	u_short th_urp;		/* urgent pointer */
};

/* UDP header */

struct sniff_udp {
	u_short uh_sport;
	u_short uh_dport;
	u_short uh_sum;
	u_short uh_plength;
};



/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

const struct sniff_ethernet *ethernet; /* The ethernet header */
const struct sniff_ip *ip; /* The IP header */
const struct sniff_tcp *tcp; /* The TCP header */
const char *payload; /* Packet payload */

u_int size_ip;
u_int size_tcp;

int size_udp = 8;
int size_icmp = 8;
int size_payload;

#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_IPV4 0x0800


void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

	printf("\n");

return;
}



void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			/* number of bytes per line */
	int line_len;
	int offset = 0;					/* zero-based offset counter */
	const u_char *ch = payload;

	if (len <= 0)
		return;

	/* data fits on one line */
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	/* data spans multiple lines */
	for ( ;; ) {
		/* compute current line length */
		line_len = line_width % len_rem;
		/* print line */
		print_hex_ascii_line(ch, line_len, offset);
		/* compute total remaining */
		len_rem = len_rem - line_len;
		/* shift pointer to remaining bytes to print */
		ch = ch + line_len;
		/* add offset */
		offset = offset + line_width;
		/* check if we have line width chars or less */
		if (len_rem <= line_width) {
			/* print last line and get out */
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

const char * eth_ntoa ( const void *ll_addr ) {
         static char buf[18]; /* "00:00:00:00:00:00" */
         const uint8_t *eth_addr = ll_addr;
         printf ( buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                   eth_addr[0], eth_addr[1], eth_addr[2],
                   eth_addr[3], eth_addr[4], eth_addr[5] );
         return buf;
 }


void StrWrapper(int strCheck_flag, char *inputStr, const struct pcap_pkthdr *header, const u_char *packet){
	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const struct sniff_udp *udp;
	const char *payload;


	//time wrapper and parser from structs of time.h & sys_types.h

	time_t raw_time = (time_t)header->ts.tv_sec;
	char *tpoint = ctime (&raw_time);
	char tbuffer[256];
	strcpy(tbuffer, tpoint);
	int rag =strlen(tbuffer); 
	tbuffer[(rag-1)] = 0;
	printf("%s",tbuffer);


	ethernet = (struct sniff_ethernet*) (packet);

	if(ntohs(ethernet->ether_type) == ETHERTYPE_IPV4){
		printf(" IPV4 ");


		//const unsigned char* mac=(unsigned char*)ntohs(ethernet->ether_shost);
		//printf("%02X:%02X:%02X:%02X:%02X:%02X\n ->",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
		printf("%s -> ", ether_ntoa(ethernet->eth_src));
		printf("%s ", ether_ntoa(ethernet->eth_dst));
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		size_ip = IP_HL(ip)*4;
		if (size_ip < 20) {
			printf("   * Invalid IP header length: %u bytes\n", size_ip);
			return;
		}

		/* print source and destination IP addresses 
		printf("%s ->", inet_ntoa(ip->ip_src));
		printf("%s", inet_ntoa(ip->ip_dst));
		*/
		if (ip->ip_p == IPPROTO_TCP) {		
			printf(" TCP ");
			/* define/compute tcp header offset */
			tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
			size_tcp = TH_OFF(tcp)*4;
			if (size_tcp < 20) {
			//	printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
				return;
			}

			printf("%s.%d -> ", inet_ntoa(ip->ip_src), ntohs(tcp->th_sport));
			printf("%s.%d ", inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));
			printf(" len %d ", ntohs(ip->ip_len));
			/* define/compute tcp payload (segment) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);


			if (size_payload > 0){
				printf(" Payload(%d) :", size_payload);
				if(inputStr != NULL){
					if (strstr(payload,inputStr) == NULL){
						printf("I m flag %d \n",strCheck_flag);
						return;
					}
				}
				if(strCheck_flag){
					int nPayload = strlen(payload);
					char removeSpace[nPayload];
					strcpy(removeSpace,payload);
					char *ptr = strtok(NULL, " ");
					ptr = strtok(NULL, " ");
					printf("%s \n", ptr);
				}
				else{
					//printf("(Payload size:%d) Payload :", size_payload);
					print_payload(payload, size_payload);
				}
			
			}
			printf("\n");
			//For next line for every protocol-packet entry
		} else if (ip->ip_p == IPPROTO_UDP) {
			printf(" UDP ");
			/* define/compute udp header offset */
			udp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
			


			printf("%s.%d -> ", inet_ntoa(ip->ip_src), ntohs(udp->uh_sport));
			printf("%s.%d ", inet_ntoa(ip->ip_dst), ntohs(udp->uh_dport));
			printf(" len %d ", ntohs(ip->ip_len));
			/* define/compute tcp payload (segment) offset */
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);



			if (size_payload > 0){
					printf(" Payload(%d) : ", size_payload);
					print_payload(payload, size_payload);
			}
			printf("\n");
		} else if (ip->ip_p == IPPROTO_ICMP) {
			printf(" ICMP ");
			printf("%s -> ", inet_ntoa(ip->ip_src));
			printf("%s ", inet_ntoa(ip->ip_dst));
			printf(" len %d ", ntohs(ip->ip_len));
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);


			if (size_payload > 0){
					printf(" Payload(%d) : ", size_payload);
					print_payload(payload, size_payload);
			}
			printf("\n");
			
		} else {
			printf(" IP ");
			payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
			/* compute tcp payload (segment) size */
			size_payload = ntohs(ip->ip_len) - (size_ip);

			if (size_payload > 0){
					printf(" Payload(%d) : ", size_payload);
					print_payload(payload,size_payload);
			}
			printf("\n");	
		}
	}
	else if (ntohs(ethernet->ether_type) == ETHERTYPE_ARP) {
		printf(" ARP \n");
	}
	 
	else {
		printf("Not defined protocol\n");
	}

	return;
}

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){

	static int count = 1;                   /* packet counter */
	
	/* declare pointers to packet headers */
	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	const struct sniff_ip *ip;              /* The IP header */
	const struct sniff_tcp *tcp;            /* The TCP header */
	const struct sniff_udp *udp;			/* The UDP header */
	const char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
//	int size_payload;


	int strCheck_flag = 0;
	char *inputStr = NULL;

	if (args != NULL) {
		char ch = *args;
		if(ch == 'g'){
			strCheck_flag =1;
			if(strlen(args+1)>0){
				inputStr = args + 1;
			}
		}else {
			inputStr = args;	
		}
		
	}
	
	if(inputStr == NULL){
		StrWrapper(strCheck_flag, inputStr, header, packet);
	}
	else{
	
		//printf("\nPacket number %d:\n", count);
		//count++;
		
		/* define ethernet header */
		ethernet = (struct sniff_ethernet*)(packet);
		
		/* Extract only if the protocol is only ipv4 */
		if (ntohs(ethernet->ether_type)== ETHERTYPE_IPV4){
		/* define/compute ip header offset */
			ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
			size_ip = IP_HL(ip)*4;
			if (size_ip < 20) {
				printf("   * Invalid IP header length: %u bytes\n", size_ip);
				return;
			}

			/* print source and destination IP addresses 
			printf(" %s -->\n", inet_ntoa(ip->ip_src));
			printf(" %s\n", inet_ntoa(ip->ip_dst));
			*/

			/* determine protocol */	
			switch(ip->ip_p) {
				case IPPROTO_TCP:
					//printf("   Protocol: TCP\n");
					/* define/compute tcp header offset */
					tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
					size_tcp = TH_OFF(tcp)*4;
					if (size_tcp < 20) {
					//	printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
						return;
					}
					/* define/compute tcp payload (segment) offset */
					payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
					/* compute tcp payload (segment) size */
					size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

					if (size_payload > 0){
						char payload_s[size_payload];
						strncpy(payload_s, payload, size_payload);
						if (strstr(payload_s,inputStr)==NULL)
							return;
						else {
							StrWrapper(strCheck_flag, inputStr, header, packet);
						}
					}
					else{
						return;
					}
					break;
				case IPPROTO_UDP:
					//printf("   Protocol: UDP\n");
					/* define/compute tcp header offset 
					tcp = (struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
					size_tcp = TH_OFF(tcp)*4;
					if (size_tcp < 20) {
						printf("   * Invalid UCP header length: %u bytes\n", size_tcp);
						return;
					}
					*/
					/* define/compute tcp payload (segment) offset */
					payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_udp);
					/* compute tcp payload (segment) size */
					size_payload = ntohs(ip->ip_len) - (size_ip + size_udp);

					if (size_payload > 0){
						char payload_s[size_payload];
						strncpy(payload_s, payload, size_payload);
						if (strstr(payload_s,inputStr)==NULL)
							return;
						else {
							StrWrapper(strCheck_flag, inputStr, header, packet);
						}
					}
					else{
						return;
					}

					return;
				case IPPROTO_ICMP:
					//printf("   Protocol: ICMP\n");
					payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_icmp);
					/* compute tcp payload (segment) size */
					size_payload = ntohs(ip->ip_len) - (size_ip + size_icmp);

					if (size_payload > 0){
						char payload_s[size_payload];
						strncpy(payload_s, payload, size_payload);
						if (strstr(payload_s,inputStr)==NULL)
							return;
						else {
							StrWrapper(strCheck_flag, inputStr, header, packet);
						}
					}
					else{
						return;
					}
					
					return;
				case IPPROTO_IP:
					//printf("   Protocol: IP\n");
						payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);
					/* compute tcp payload (segment) size */
					size_payload = ntohs(ip->ip_len) - (size_ip);

					if (size_payload > 0){
						char payload_s[size_payload];
						strncpy(payload_s, payload, size_payload);
						if (strstr(payload_s,inputStr)==NULL)
							return;
						else {
							StrWrapper(strCheck_flag, inputStr, header, packet);
						}
					}
					else{
						return;
					}
					return;
				default:
					//printf("   Protocol: Not defined in my code\n");
					return;
				}
			}
	}
}

int main(int argc, char **argv)
{

	char *dev = NULL;			/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];		/* error buffer */
	pcap_t *handle;				/* packet capture handle */

	char filter_exp[] = "ip";		/* filter expression [3] */
	struct bpf_program fp;			/* compiled filter program (expression) */
	bpf_u_int32 mask;			/* subnet mask */
	bpf_u_int32 net;			/* ip */

	int inputOptions = 0;
	char *interface = NULL;
	char *file = NULL;
	char *string = NULL;
	int type_0x800 = 0;
	char *expression = NULL;
	struct bpf_program filter;
	char filter_string[] = "(tcp port http) && ((tcp[32:4] = 0x47455420) || (tcp[((tcp[12:1] & 0xf0) >> 2):4] = 0x504f5354))";

	struct pcap_pkthdr header;
	const u_char *packet;
	int cnt = -1;

	while ((inputOptions = getopt(argc, argv, "i:r:s:g")) != -1) {
		switch(inputOptions) {
			case 'i':
				interface = optarg;
				break;
			case 'r':
				file = optarg;
				break;
			case 's':
				string = optarg;
				break;
			case 'g':
				type_0x800 = 1;
				break;
			case '?':
				if (optopt == 'i') {
					printf("No interface?\n");
					return 0;
				} else if (optopt == 'r') {
					printf("file name?\n");
					return 0;
				} else if (optopt == 's') {
					printf("String case not right\n");
					return 0;
				} else {
					printf("Unknown argument!\n");
					return 0;
				}
			default:
				printf("Default case?!\n");
				return 0;
		}
		
	}
	
	/* check the input args and parse checks */
	if (optind == argc - 1)
		expression = argv[optind];
	else if (optind < argc -1) {
		printf("Less args than expected\n");
		return 0;
	}
	
	if (interface != NULL && file != NULL) {
		printf("You can only use interface OR file!\n");
		return 0;
	}
	
	if (interface == NULL && file == NULL) {
		/* find a capture device if not specified on command-line */
		interface = pcap_lookupdev(errbuf);
		if (interface == NULL) {
			printf("Couldn't find default device: %s\n", errbuf);
			return 0;
		}
	}
	
	printf("\nLets start Passive Network Monitoring:\n");
	
	/* Interface & file case */
	if (interface != NULL && file == NULL) {
		/* get network number and mask associated with capture device */
		if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
			printf("Couldn't get netmask for device %s: %s\n", errbuf);
			net = 0;
			mask = 0;
		}
		/* open capture device */
		handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) {
			printf("Couldn't open device %s: %s\n", errbuf);
			return 0;
		}
	} else if (interface == NULL && file != NULL) {
		handle = pcap_open_offline(file, errbuf);
		if (handle == NULL) {
			printf("Error message: %s\n\n", errbuf);
			return 0;
		}
	} else {
		return 0;
	}
	
	
	if (pcap_datalink(handle) != DLT_EN10MB) {
		printf("Interface %s \n", interface);
		return 0;
	}
	
	/* http filter mode */
	if (type_0x800) {
		
		if (pcap_compile(handle, &filter, filter_string, 0, net) == -1) {
			printf("Couldn't parse filter %s: %s\n", pcap_geterr(handle));
			return 0;
		}
		
		if (pcap_setfilter(handle, &filter) == -1) {
			printf("Couldn't install filter %s: %s\n", pcap_geterr(handle));
			return 0;
		}
	}
	
	
	if (expression != NULL) {
		
		if (pcap_compile(handle, &filter, expression, 0, net) == -1) {
			printf("Couldn't parse filter %s: %s\n", pcap_geterr(handle));
			return 0;
		}
		
		if (pcap_setfilter(handle, &filter) == -1) {
			printf("Couldn't install filter %s: %s\n", pcap_geterr(handle));
			return 0;
		}
	}

	/*checks for finding out if it is http or not */
	if (type_0x800) {
		int len = 0;
		if (string != NULL)
			len = strlen(string);
		char *tmp = (char *)malloc(len+2);
		strcpy(tmp, "g");
		if (string != NULL)
			strcat(tmp, string);
		
		pcap_loop(handle, cnt, got_packet, tmp);
	} else {
		pcap_loop(handle, cnt, got_packet, string);
	}

	pcap_close(handle);
	printf("\n\t capture complete\n\n");
	return 0;
}
