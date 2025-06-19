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
#include <arp.h>
#include <parse.h>

// Keyboard interrupt handler
int sigintFl = 0;
void sigintHandler(int signal){
    sigintFl = 1;
    printf("\n");
}

int main(int argc,char** argv){
    // sudo sysctl net.ipv4.ip_forward=0
    int retv = 0;
    if(argc < 3){
        printf("usage: sudo ./dpi \"ifname\" \"target ip\"\n");
        return 1;
    }
    // Parse args
    char* ifname = argv[1];
    uint8_t targetIp[4] = {0};
    ip2arr(argv[2],targetIp);
    uint8_t routerIp[4] = {0};
    memcpy(routerIp,targetIp,3);
    routerIp[3] = 1;
    // Local adresses
    uint8_t localMac[6] = {0};
    uint8_t localIp[4] = {0};
    getInterfaceMac(ifname,localMac);
    getInterfaceIp(ifname,localIp);
    printf("Local ip: %d.%d.%d.%d\n",localIp[0],localIp[1],localIp[2],localIp[3]);
    printf("Local mac: %02x:%02x:%02x:%02x:%02x:%02x\n",localMac[0],localMac[1],localMac[2],localMac[3],localMac[4],localMac[5]);
    // Get router macaddress
    uint8_t routerMac[6] = {0};
    Arp_t arp;
    arp.getMac(ifname,routerIp,routerMac);
    printf("---------------------\n");
    printf("Router ip: %d.%d.%d.%d\n",routerIp[0],routerIp[1],routerIp[2],routerIp[3]);
    printf("Router mac: %02x:%02x:%02x:%02x:%02x:%02x\n",routerMac[0],routerMac[1],routerMac[2],routerMac[3],routerMac[4],routerMac[5]);
    // Get target mac address
    uint8_t targetMac[6] = {0};
    arp.restore();
    arp.getMac(ifname,targetIp,targetMac);
    printf("---------------------\n");
    printf("Target ip: %d.%d.%d.%d\n",targetIp[0],targetIp[1],targetIp[2],targetIp[3]);
    printf("Target mac: %02x:%02x:%02x:%02x:%02x:%02x\n",targetMac[0],targetMac[1],targetMac[2],targetMac[3],targetMac[4],targetMac[5]);
    // Socket for data forwarding
    int sockForward = socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_IP));
    if(sockForward < 0){
        printf("Socket creation failed\n");
        return -1;
    }
    sockaddr_ll bindAddr = {0};
    fillBindAddr(&bindAddr,ifname,ETH_P_ALL);
    bind(sockForward,(sockaddr*)&bindAddr,sizeof(sockaddr_ll));
    // Router and target addresses
    sockaddr_ll routerAddr = {0};
    fillDestAddr(&routerAddr,ifname,routerMac,ETH_P_IP);
    sockaddr_ll targetAddr = {0};
    fillDestAddr(&targetAddr,ifname,targetMac,ETH_P_IP);
    // Start forwarding
    printf("Forwarding...\n");
    pollfd fds[1];
    fds[0].fd = sockForward;
    fds[0].events = POLLIN;
    // Enable keyboard interrupt handler
    signal(SIGINT,sigintHandler);
    while(!sigintFl){
        retv = poll(fds,1,1000); // 1 s timeout
        if(retv < 0){
            printf("Socket poll error\n");
            break;
        }
        // Forwarding socket recieved data
        if(fds[0].revents & POLLIN){
            fds[0].revents = 0;
            Ipv4Parser ip;
            int recvDataLen = recvfrom(sockForward,ip.buffer,PCKT_BUF_SIZE,0,NULL,NULL);
            if(!ip.check()){
                ip.parse();
                int targetSrc = memcmp(ip.srcIp,targetIp,4);
                int targetDest = memcmp(ip.destIp,targetIp,4);
                // Forward to router
                if(targetSrc == 0){
                    int blocked = 0;
                    if(ip.protocol == 6){
                        TcpParser tcp(&ip);
                        tcp.parse();
                        uint16_t dataLen = ip.pcktLen - ip.hdrLen - tcp.tcpHdrLen;
                        if((dataLen>0) and (findTlsClientHello(tcp.tcpData)==0)){
                            char sni[1024] = {0};
                            extractSni(tcp.tcpData,dataLen,sni);
                            char* result = strstr(sni,"mail");
                            if(result != NULL){
                                blocked = 1;
                                printf("BLOCKED\n");
                            }
                            printf("%s\n",sni);
                            printf("%i.%i.%i.%i\n",ip.destIp[0],ip.destIp[1],ip.destIp[2],ip.destIp[3]);
                            printf("-------------------------\n");
                        }  
                    }
                    if(!blocked){
                        sendto(sockForward,ip.buffer,recvDataLen,0,(sockaddr*)&routerAddr,sizeof(routerAddr));
                    }
                    //printf("Forwarded to router\n");
                }
                // Forward to target
                if(targetDest == 0){
                    sendto(sockForward,ip.buffer,recvDataLen,0,(sockaddr*)&targetAddr,sizeof(targetAddr));
                    //printf("Forwarded to target\n");
                }
            }
            
        }
    }
    printf("Forwarding stopped\n");
    close(sockForward);
    return 0;
}