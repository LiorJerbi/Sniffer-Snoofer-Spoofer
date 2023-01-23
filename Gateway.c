#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>






#define PORT 31553
#define PORTP1 31554

int main(int argc, char *argv[])
{
    if (argc < 2)
    {
        printf("Usage: %s <ip>\n", argv[0]);
        return 1;
    }
    char *host_name = argv[1];
    // struct hostent * entry = gethostbyname(host_name);
    // if(entry == NULL){
    //     perror("gethostbyname\n");
    //     exit(1); 
    // }


    struct sockaddr_in listen;
    memset(&listen, 0, sizeof(listen));
    listen.sin_family = AF_INET;
    listen.sin_addr.s_addr =INADDR_ANY;
    listen.sin_port = htons(PORT);
    socklen_t lenlis = sizeof(listen);

    char buffer[1500];
    int listening_socket = socket(AF_INET, SOCK_DGRAM, 0);

    if (listening_socket == -1)
    {
        perror("Could not create listening socket.\n");
        close(listening_socket);
        return 0;
    }

    if((bind(listening_socket,(struct sockaddr *)&listen,lenlis))<0){
        perror("Could not bind listening socket.\n");
        close(listening_socket);
        return 0;
    }

    int up_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (up_socket == -1)
    {
        perror("Could not create listening socket.\n");
        close(up_socket);
        return 0;
    }
    struct sockaddr_in host;
    memset(&host, 0, sizeof(host));
    host.sin_family = AF_INET;
    host.sin_port = htons(PORTP1);
    host.sin_addr.s_addr=inet_addr(host_name);
    socklen_t lenhos = sizeof(host);

    
    int byteRec;
    while (1)
    {
       if((byteRec = recvfrom(listening_socket,buffer,1500,0,(struct sockaddr *)&listen,&lenlis))<0){
            perror("recv() error.\n");
            return 0;    
        
        }
        float rand = ((float)(random())/((float)RAND_MAX));
        /*This demonstrate the 50% packet loss on the net*/
        if(rand>0.5){


            int bytesent;
            if((bytesent = sendto(up_socket,buffer,1500,0,(struct sockaddr *)&host,lenhos))<0){
                perror("send() error.\n");
                return 0; 
            }
            char srcip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &host.sin_addr, srcip, INET_ADDRSTRLEN);
            printf("DataGram Forwarded To Ip: %s,Port: %d\n\n",srcip,ntohs(host.sin_port));
        }
        else{
            printf("DataGram Lost, rand is:%f\n\n",rand);
        }




    }
    close(listening_socket);
    close(up_socket);
    return 0;
}