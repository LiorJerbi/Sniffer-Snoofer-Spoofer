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
#include <netinet/ether.h>
#include "arpa/inet.h"
#include <errno.h>


//#### Task A - Sniffer ####//

/*Application Layer*/
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
    struct ether_header *eth = (struct ether_header *)packet;
    const struct ip * ip = (struct ip *)(packet + sizeof(struct ether_header));
    char srcip[INET_ADDRSTRLEN], dstip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &ip->ip_src, srcip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &ip->ip_dst, dstip, INET_ADDRSTRLEN);
    counter++;
    /* determine protocol */
                                  
        FILE *fp;
        fp = fopen("314899493_315538454","a+");     //the file we want to send
        if(fp== NULL){
            perror("failed open file\n");
            return;
        }
        int ip_header_len = ip->ip_hl *4;
        struct tcphdr * tcp = (struct tcphdr*)(packet+sizeof(struct ether_header )+ip_header_len); 
        uint16_t size_tcp = tcp->doff*4;
        struct appheader * app = (struct appheader *)(packet + sizeof(struct ether_header ) + ip_header_len + size_tcp);

        uint16_t flags = ntohs(app->flags);
        uint16_t status = ntohs(app->flags) & 0x3ff;
        uint32_t untime = ntohl(app->unixtime);
        uint16_t app_len = ntohs(app->length);


        unsigned char* payload = (unsigned char*) (packet + sizeof(struct ether_header ) + ip_header_len + size_tcp);
        unsigned int paySize = header->len - sizeof(struct ether_header ) - ip_header_len - size_tcp;
    
    
        if(tcp->psh){
            fprintf(fp,"\n\nsource_ip:<%s>,dest_ip<%s>,source_port<%d>,dest_port<%d>,timestamp:<%u>,total_length:<%hu>,cache_flag:<%hu>,steps_flag:<%hu>,type_flag:<%hu>,status_code:<%u>,cache_control:<%d>,data:<\n"
                        ,srcip,dstip,ntohs(tcp->th_sport),ntohs(tcp->th_dport),untime,app_len,(flags&app->c_flag),
                        (flags&app->s_flag),(flags&app->t_flag),status,ntohs(app->cache));
        
            for (int i = 0; i < paySize; ++i){
                if (!(i & 15)){
                    fprintf(fp, "\n%04X: ", i);
                }
                fprintf(fp, "%02X ", ((unsigned char *)payload)[i]);
            }
            fprintf(fp,">\n\n\n");
            
            printf(" \n ****************************************************** \n");
            printf("  ************* FRAME NUM %d ********************************* \n",counter);
            printf("--->Sent from IP Address:%s  Src_PORT:%d    To IP Adress:%s  Dst_PORT:%d   \n",srcip,ntohs(tcp->th_sport),dstip,ntohs(tcp->th_dport));
            printf("--->Unix Time:%u\n--->AppHeader Size:%d\n--->Flags<--\n:--->Cache:[%d]\n--->Steps:[%d]\n--->Type:[%d]  \n",ntohl(app->unixtime),app_len,(flags&app->c_flag),(flags&app->s_flag),(flags&app->t_flag));
            printf("--->Status:[%d]\n--->Cache Control[%d]\n",status,ntohs(app->cache));
            for (int i = 0; i < paySize; ++i){
                if (!(i & 15)){
                    printf("\n%04X: ", i);
                }
                printf(" %02X ", ((unsigned char *)payload)[i]);
            }
        }
        else{
            fprintf(fp,"\n\nsource_ip:<%s>,dest_ip<%s>,source_port<%d>,dest_port<%d>\n -->App header Not Exsist--<\n"
            ,srcip,dstip,ntohs(tcp->th_sport),ntohs(tcp->th_dport));
            printf(" \n ****************************************************** \n");
            printf("  ************* FRAME NUM %d ********************************* \n",counter);
            printf("\n--->Sent from IP Address: %s  Src_PORT: %d    To IP Adress: %s  Dst_PORT: %d   \n\n",srcip,ntohs(tcp->th_sport),dstip,ntohs(tcp->th_dport));
        }
        fclose(fp);
        printf("\n");
        return;
        
 
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