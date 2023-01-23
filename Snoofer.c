#include <stdio.h>
#include <pcap.h>
#include <string.h>
//#include <netinet/ip.h>
#include <netinet/tcp.h>
#include "arpa/inet.h"
#include <sys/types.h> 
#include <stdlib.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>




#define ICMP_ECHO_REQ 8



struct icmpheader {
    unsigned char icmp_type; // ICMP message type
    unsigned char icmp_code; // Error code
    unsigned short int icmp_chksum; //Checksum for ICMP Header and data
    unsigned short int icmp_id;     //Used for identifying request
    unsigned short int icmp_seq;    //Sequence number
};
struct ipheader {
    unsigned char      iph_ihl:4, //IP header length
    iph_ver:4; //IP version
    unsigned char      iph_tos; //Type of service
    unsigned short int iph_len; //IP Packet length (data + header)
    unsigned short int iph_ident; //Identification
    unsigned short int iph_flag:3, //Fragmentation flags
    iph_offset:13; //Flags offset
    unsigned char      iph_ttl; //Time to Live
    unsigned char      iph_protocol; //Protocol type
    unsigned short int iph_chksum; //IP datagram checksum
    struct  in_addr    iph_sourceip; //Source IP address
    struct  in_addr    iph_destip;   //Destination IP address
};


unsigned short in_cksum(unsigned short *buf, int length);



void send_raw_ip_packet(struct ipheader* ip){
    struct sockaddr_in dest_info;
    int enable = 1;

    // Step 1: Create a raw network socket.
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    // Step 2: Set socket option.
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, 
                     &enable, sizeof(enable));

    // Step 3: Provide needed information about destination.
    dest_info.sin_family = AF_INET;
    dest_info.sin_addr = ip->iph_destip;

    // Step 4: Send the packet out.
    sendto(sock, ip, ntohs(ip->iph_len), 0,(struct sockaddr *)&dest_info, sizeof(dest_info));
    close(sock);
}

void got_packet(u_char *args, const struct pcap_pkthdr *header ,const u_char *packet){

    char fake_packet[1500];
    memset(fake_packet,0,1500);
    
    struct ipheader * ip = (struct ipheader *)(packet + 14); // 14 is the size of Eth hedaer (Internet Layer)
    struct icmpheader * icmp =  (struct icmpheader *)(packet + ip->iph_ihl*4 + 14);
    
    if(icmp->icmp_type==ICMP_ECHO_REQ){  //if 8 is Echo request we want to change.
        struct ipheader * fake_ip = (struct ipheader *)(fake_packet + 14); 
        struct icmpheader * fake_icmp =  (struct icmpheader *)(fake_packet + ip->iph_ihl*4 + 14);   
        // char *fake_msg = (char*)(sizeof(struct icmpheader )+fake_packet + ip->iph_ihl*4 + 14);
        // fake_msg = "Fooled by Assaf and Lior";
        fake_icmp->icmp_type=0;
        fake_icmp->icmp_code=icmp->icmp_code;
        fake_icmp->icmp_id=icmp->icmp_id;
        fake_icmp->icmp_seq=icmp->icmp_seq;
        fake_icmp->icmp_chksum=in_cksum((unsigned short *)fake_icmp,sizeof(struct icmpheader));

        fake_ip->iph_destip = ip->iph_sourceip;
        fake_ip->iph_sourceip = ip->iph_destip;
        fake_ip->iph_flag = ip->iph_flag;
        fake_ip->iph_ident = ip->iph_ident;
        fake_ip->iph_ihl = ip->iph_ihl;
        fake_ip->iph_len = ip->iph_len;
        fake_ip->iph_offset = ip->iph_offset;
        fake_ip->iph_protocol = ip->iph_protocol;
        fake_ip->iph_tos = ip->iph_tos;
        fake_ip->iph_ttl = ip->iph_ttl;
        fake_ip->iph_ver = ip->iph_ver;
        fake_ip->iph_chksum = ip->iph_chksum;
        char srcip[INET_ADDRSTRLEN], dstip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &fake_ip->iph_sourceip, srcip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &fake_ip->iph_destip, dstip, INET_ADDRSTRLEN);
        printf("Spoofed icmp packet from: %s to: %s ",srcip,dstip);
        send_raw_ip_packet(fake_ip);
        

    }


    return;
        
 
 }

int main()
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "icmp";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	

	/* Open the session in promiscuous mode */
	handle = pcap_open_live("br-ccc8bcc8410d", BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
    }
	// Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);                

    pcap_close(handle);   //Close the handle 
    return 0;
}
unsigned short in_cksum (unsigned short *buf, int length)
{
   unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   /*
    * The algorithm uses a 32 bit accumulator (sum), adds
    * sequential 16 bit words to it, and at the end, folds back all 
    * the carry bits from the top 16 bits into the lower 16 bits.
    */
   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

   /* treat the odd byte at the end, if any */
   if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   /* add back carry outs from top 16 bits to low 16 bits */
   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);
}


