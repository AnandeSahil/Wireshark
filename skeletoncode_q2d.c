// Compile with "gcc encap.c -o encap" with minGW

#define _LARGEFILE64_SOURCE    1

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/stat.h> 
#include <unistd.h>
#include <sys/types.h>
#include "encap.h"
#include <arpa/inet.h>
#include <string.h>


u_short ush_endian_swp(u_short p);
unsigned int uint_endian_swp(unsigned int p);
int isgetTCPIP(BYTE *pcktbuf, u_int *size_ip, u_int *size_tcp,FILE *);

struct sniff_ethernet *ethernet;  /* The ethernet header */
struct sniff_tcp *tcp; /* The TCP header */
struct sniff_ip *ip;  /* The IP header */
char *payload; /* Packet payload */

main(int argc,char **argv)
{
	FILE *InRaw,*fp;
	struct stat filedat;
	off64_t InLen, currpos;
	struct pcap_file_header pcapfilehdr;
	struct pcap_pkthdr pckthdr;
	BYTE pcktbuf[65535];
	u_int size_ip;
	u_int size_tcp;
	unsigned int pcktcnt=0;
	int totalsize = 0;

	// Defining Source IPv4 Address in individual bytes
	int check_ip1 = 129;
	int check_ip2 = 21;
	int check_ip3 = 27;
	int check_ip4 = 161;
	

	if(argc<2) 
		{
		printf("ERROR: Too few input arguments\n");
		printf("Usage: encap input.pcap \n");
		return 0;
		}
	if(stat(*(argv+1),&filedat)==-1)
		{
		printf("ERROR: Can't get length of input file\n");
		return 0;
		}
	InLen=filedat.st_size;

	if((fp=fopen("outdata_q2d.txt", "w")) == NULL) {
		printf("Cannot open outdata_q2d.txt file.\n");
		return(0);
	  }

	InRaw=fopen64(*(argv+1),"rb");
	if(InRaw==NULL)
		{
		printf("ERROR: Can't open file\n");
		return(0);
		}


	printf("Done \n\n",InLen);
	if (fread((char *) &pcapfilehdr, sizeof(pcapfilehdr), 1, InRaw) != 1) {
		printf("0) Fread for pcap file header failed\n");
		return(-1);
	}


	currpos = ftello64(InRaw);

	while (currpos < InLen){

		pcktcnt++;
		currpos = ftello64(InRaw);
		if (fread((char *) &pckthdr, sizeof(pckthdr), 1, InRaw) != 1) {
			break;
		}

		if (fread((char *) &pcktbuf, pckthdr.caplen, 1, InRaw) != 1) {
				break;
		}

		/* Find stream in file, count packets and get size (in bytes) */
		if( isgetTCPIP(pcktbuf, &size_ip, &size_tcp,fp)){
			/* Simple example code */
			u_short ip_frame_length = ush_endian_swp(ip->ip_len);

			u_short tcp_packet_length = ip_frame_length - size_ip;

			u_short i_packet_size = tcp_packet_length - size_tcp;

		
			totalsize += i_packet_size;

			unsigned int seq_no = uint_endian_swp(tcp->th_seq);
			unsigned int ack_no = uint_endian_swp(tcp->th_ack);

			BYTE one_s =ip->ip_src.S_un.S_un_b.s_b1;		// Source IPv4 address in standard format of four 8-bit decimal numbers separated by dots
			BYTE two_s =ip->ip_src.S_un.S_un_b.s_b2;		// Accessing indiviudal 8 bits from inside the struct and union
			BYTE three_s =ip->ip_src.S_un.S_un_b.s_b3;
			BYTE four_s =ip->ip_src.S_un.S_un_b.s_b4;

			
			// Check if payload is actually containing data or not
			if (i_packet_size != 0)
			{
				// Last data sent by Receiver is not the fragment of file transmission thus discarded. Only transmission from Source is considered
				if (check_ip1==one_s && check_ip2==two_s && check_ip3==three_s && check_ip4==four_s) 
				{
					fprintf(fp, "Packet no.: %d, Size of Payload is  %u bytes, Sequence Number: %u\n",pcktcnt, i_packet_size, seq_no);	
				}
				
			}

			
		}  // isgetTCPIP

	} //while currpos < InLen

	fprintf(fp, "Total file size is %d bytes\n",totalsize);
	fclose(InRaw);
	fclose(fp);

	return(0);

}

u_short ush_endian_swp(u_short p)
{
    	u_short res;
    	char *h = (char *)(&p);
    	char *hr = (char *)(&res);

	hr[0]=h[1];
	hr[1]=h[0];

	return res;
}

unsigned int uint_endian_swp(unsigned int p)
{
    	unsigned int res;
    	char *h = (char *)(&p);
    	char *hr = (char *)(&res);

	hr[0]=h[3];
	hr[1]=h[2];
	hr[2]=h[1];	
	hr[3]=h[0];

	return res;
}


int isgetTCPIP(BYTE *pcktbuf, u_int *size_ip, u_int *size_tcp,FILE *fp)
{
		ethernet = (struct sniff_ethernet*)(pcktbuf);

		if(ush_endian_swp(ethernet->ether_type) == IPTYPEETHER){ // IP only past here  //Check if it is IPv4 address

			ip = (struct sniff_ip*)(pcktbuf + SIZE_ETHERNET);
			
			*size_ip = IP_HL(ip)*4;
			if (*size_ip < 20) {
				printf("   * Invalid IP header length: %u bytes\n", *size_ip);
				return 0;
			}

			if(ip->ip_p == TCPPRTCL){ // TCP only past here
				tcp = (struct sniff_tcp*)(pcktbuf + SIZE_ETHERNET + *size_ip);
				*size_tcp = TH_OFF(tcp)*4;

				if (*size_tcp < 20) {
					printf("   * Invalid TCP header length: %u bytes\n", *size_tcp);
					return 0;
				}
				payload = (u_char *)(pcktbuf + SIZE_ETHERNET + *size_ip + *size_tcp);

				return 1;
			} // only TCP
		} // only IP
		return 0;
}



