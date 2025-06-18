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

// Keyboard interrupt handler
int sigintFl = 0;
void sigintHandler(int signal){
    sigintFl = 1;
    printf("\n");
}

#define PCKT_BUF_SIZE 4096

class Ipv4Parser{
public:
    uint8_t buffer[PCKT_BUF_SIZE] = {0};
    uint16_t hdrLen = 0;
    uint16_t pcktLen = 0;
    uint8_t ttl = 0;
    uint8_t protocol = 0;
    uint8_t* srcIp = &buffer[12];
    uint8_t* destIp = &buffer[16];
    // Parse IPv4 packet
    uint8_t parse(){
        hdrLen = (buffer[0] & 0xf)<<2;
        pcktLen = buffer[2]<<8 | buffer[3];
        ttl = buffer[8];
        protocol = buffer[9];
        return 0;
    }
    // Check IP version
    uint8_t check(){
        uint8_t version = (buffer[0] >> 4) & 0xf;
        if(version == 4){
            return 0;
        } else {
            return 1;
        }
    }
};

class TcpParser{
public:
    uint8_t* tcpHdr = nullptr;
    uint8_t* tcpData = nullptr;
    uint16_t srcPort;
    uint16_t destPort;
    uint16_t tcpHdrLen;
    TcpParser(Ipv4Parser* hdr){
        tcpHdr = &hdr->buffer[hdr->hdrLen];
    }
    //
    uint8_t parse(){
        srcPort = tcpHdr[0]<<8 | tcpHdr[1];
        destPort = tcpHdr[2]<<8 | tcpHdr[3];
        tcpHdrLen = ((tcpHdr[12]>>4) & 0xf) << 2;
        tcpData = &tcpHdr[tcpHdrLen];
        return 0;
    }
};

uint8_t findTlsClientHello(uint8_t* data){
    if((data[0]==22) and (data[1]==3) and (data[5]==1)){
        return 0;
    } else{
        return 1;
    }
}

uint8_t extractSni(uint8_t* data,uint64_t dataLen,char* sni){
    uint64_t ptr = 5; // TLS hdr
    ptr = ptr + 6; // Client hello hdr
    ptr = ptr + 32; // Random
    ptr = data[ptr] + 1 + ptr; // Session ID
    ptr = (data[ptr]<<8 | data[ptr+1]) + 2 + ptr; // Chipher suits
    ptr = data[ptr] + 1 + ptr; // Compression methods
    ptr = ptr + 2; // Extensions len
    // Parse extensions
    uint16_t extType;
    uint16_t extLen;
    while(ptr<dataLen){
        extType = data[ptr]<<8 | data[ptr+1];
        extLen = data[ptr+2]<<8 | data[ptr+3];
        if(extType==0){
            ptr = ptr + 4;
            break;
        }   
        else
            ptr = ptr + 4 + extLen;
    }
    ptr = ptr + 3; // Sni hdr
    uint16_t sniLen = data[ptr]<<8 | data[ptr+1];
    memcpy(sni,&data[ptr+2],sniLen);
    sni[sniLen] = '\0';
    return 0;
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