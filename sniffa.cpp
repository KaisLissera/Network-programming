#include <stdio.h>
#include <cstring>
#include <stdint.h>
#include <csignal>

#include <sys/socket.h> // socket
#include <poll.h> // poll
#include <linux/if_packet.h> // sockaddr_ll
#include <net/ethernet.h> // ETH_P_IP
#include <unistd.h> // close

#include <common.h>
#include <parse.h>

// Keyboard interrupt handler
int sigintFl = 0;
void sigintHandler(int signal){
    sigintFl = 1;
    printf("\n");
}

int main(){
    // Create socket and bind to interface
    int sockFd = socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IP));
    if(sockFd < 0){
        printf("Socket creation failed\n");
        return -1;
    }
    char* ifname = (char*)"eth0";
    sockaddr_ll bindAddr = {0};
    fillBindAddr(&bindAddr,ifname,ETH_P_ALL);
    bind(sockFd,(sockaddr*)&bindAddr,sizeof(sockaddr_ll));
    // Listen on socket
    signal(SIGINT,sigintHandler);
    Ipv4Parser ipHdr;
    uint8_t srcIp[4];
    uint8_t destIp[4];
    while(!sigintFl){
        recvfrom(sockFd,ipHdr.buffer,PCKT_BUF_SIZE,0,NULL,NULL);
        if(ipHdr.check() == 0){
            ipHdr.parse();
            // TCP
            if(ipHdr.protocol == 6){
                TcpParser tcp(&ipHdr);
                tcp.parse();
                uint16_t dataLen = ipHdr.pcktLen - ipHdr.hdrLen - tcp.tcpHdrLen;
                if((dataLen>0) and (findTlsClientHello(tcp.tcpData)==0)){
                    //printRaw(tcp.tcpData,32);
                    memcpy(srcIp,ipHdr.srcIp,4);
                    memcpy(destIp,ipHdr.destIp,4);
                    char sni[1024] = {0};
                    extractSni(tcp.tcpData,dataLen,sni);
                    printf("%s\n",sni);
                    printf("%i.%i.%i.%i:%i -> %i.%i.%i.%i:%i\n",srcIp[0],srcIp[1],srcIp[2],srcIp[3],tcp.srcPort,destIp[0],destIp[1],destIp[2],destIp[3],tcp.destPort);
                    printf("-------------------------\n");
                }  
            }
        }
    }
    close(sockFd);
    return 0;
}