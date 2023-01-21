#include <stdio.h>
#include <pcap.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/types.h> 
#include <stdlib.h>


//#### Task A - Sniffer ####//
/* ethernet headers are always exactly 14 bytes */
#define SIZE_ETHERNET 14

/* ETH header*/
struct ethheader {
  u_char  ether_dhost[ETHER_ADDR_LEN]; /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN]; /* source host address */
  u_short ether_type;                  /* IP? ARP? RARP? etc */
};

/* IP Header */
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

/* Transport Layer*/
struct tcpheader {
	u_short th_sport;	/* source port */
	u_short th_dport;	/* destination port */
	tcp_seq th_seq;		/* sequence number */
	tcp_seq th_ack;		/* acknowledgement number */
	u_char th_offx2;	/* data offset, rsvd */
    #define TH_OFF(th)	(((th)->th_offx2 & 0xf0) > 4)
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

/*
Application Layer*/
struct appheader{
    uint32_t unixtime;
    uint16_t length;

    union
    {
        uint16_t flags;
        uint16_t _:3, c_flag:1, s_flag:1, t_flag:1, status:10;
    };
    
    uint16_t cache;
    uint16_t __;
};

int counter=0;
void got_packet(u_char *args, const struct pcap_pkthdr *header, 
        const u_char *packet)
{
    struct ethheader *eth = (struct ethheader *)packet;
  if (ntohs(eth->ether_type) == 0x0800) { // 0x0800 is IP type
    struct ipheader * ip = (struct ipheader *)
                           (packet + sizeof(struct ethheader)); 
    printf("       From: %s\n", inet_ntoa(ip->iph_sourceip));  
    printf("         To: %s\n", inet_ntoa(ip->iph_destip)); 
    counter++;
    /* determine protocol */
    switch(ip->iph_protocol) {                               
        case IPPROTO_TCP:
        FILE *fp;
        fp = fopen("314899493_315538454","a");     //the file we want to send
        if(fp== NULL){
            perror("failed open file\n");
            return;
        }
        int ip_header_len = ip->iph_ihl * 4;
        struct tcpheader * tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + ip_header_len);
        uint16_t size_tcp = tcp->th_offx2*4;
        struct appheader * app = (struct appheader *)(packet + sizeof(struct ethheader) + ip_header_len + size_tcp);
        uint16_t flags = ntohs(app->flags);
        uint16_t status = app->status;
        uint32_t untime = ntohl(app->unixtime);
        uint16_t app_len = ntohs(app->length);
        char *payload = (char *)malloc(sizeof(uint8_t)*app_len);
        memcpy(payload,(packet + sizeof(struct ethheader) + ip_header_len + size_tcp +sizeof(struct appheader) ),app_len);
        fprintf(fp,"source_ip:<%s>,dest_ip<%s>,source_port<%d>,dest_port<%d>,timestamp:<%u>,total_length:<%hu>,cache_flag:<%hu>,steps_flag:<%hu>,type_flag:<%hu>,status_code:<%u>,cache_control:<%d>,\n"
                    ,inet_ntoa(ip->iph_sourceip),inet_ntoa(ip->iph_sourceip),ntohs(tcp->th_sport),ntohs(tcp->th_dport),untime,app_len,(flags&app->c_flag),
                    (flags&app->s_flag),(flags&app->t_flag),status,ntohs(app->cache));
        for (int i = 0; i < app_len; ++i){
            if (!(i & 15)){
                fprintf(fp, "\n%04X: ", i);
            }
            fprintf(fp, "%02X ", ((unsigned char *)payload)[i]);
        }
        fprintf(fp,"\n\n\n");
        fclose(fp);
        printf(" \n ****************************************************** \n");
        printf("  ************* FRAME NUM %d ********************************* \n",counter);
        printf("--->Sent from IP Address:%s  Src_PORT:%d    To IP Adress:%s  Src_PORT:%d   \n",inet_ntoa(ip->iph_sourceip),ntohs(tcp->th_sport),inet_ntoa(ip->iph_sourceip),ntohs(tcp->th_dport));
        printf("--->Unix Time:%u\n--->Packet Size:%d\n--->Flags<--\n:--->Cache:[%d]\n--->Steps:[%d]\n--->Type:[%d]  \n",ntohl(app->unixtime),app->length,(flags&app->c_flag),(flags&app->s_flag),(flags&app->t_flag));
        printf("--->Status:[%d]\n--->Cache Control[%d]\n",status,ntohs(app->cache));
        for (int i = 0; i < app_len; ++i){
            if (!(i & 15)){
                printf("\n%04X: ", i);
            }
            printf(" %02X ", ((unsigned char *)payload)[i]);
        }
        printf("\n");
        free(payload);
        return;
        case IPPROTO_UDP:
            printf("   Protocol: UDP\n");
            return;
        case IPPROTO_ICMP:
            printf("   Protocol: ICMP\n");
            return;
        default:
            printf("   Protocol: others\n");
            return;
    }
  }
   printf("Got a packet\n");
}

int main()
{
	pcap_t *handle;			/* Session handle */
	char *dev;			/* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	struct bpf_program fp;		/* The compiled filter */
	char filter_exp[] = "tcp";	/* The filter expression */
	bpf_u_int32 mask;		/* Our netmask */
	bpf_u_int32 net;		/* Our IP */
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	/* Define the device */
	dev = "lo";//pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
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