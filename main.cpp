#include <stdio.h>
#include <cstring>
#include <stdint.h>

#include <sys/socket.h> // socket
#include <linux/if_packet.h> // sockaddr_ll
#include <net/ethernet.h> // ETH_P_IP
#include <unistd.h> // close

#include "net/common.h"
#include "net/arp.h"

int main(int argc,char** argv){
    int retv = 0;
    // Interface name
    char* ifname = (char*)"eth0";
    /*
    // ARP socket
    int sockFd = socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_ARP));
    if(sockFd < 0){
        printf("Socket creation failed\n");
        return -1;
    }
    // Address for binding socket
    sockaddr_ll bindAddr = {0};
    fillBindAddr(&bindAddr,ifName,ETH_P_ARP);
    retv = bind(sockFd,(sockaddr*)&bindAddr,sizeof(sockaddr_ll));
    // Broadcast address
    uint8_t broadcastMac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    sockaddr_ll broadcastAddr = {0};
    fillDestAddr(&broadcastAddr,ifName,broadcastMac,ETH_P_ARP);
    // Local interface addresses
    uint8_t localMac[6] = {0};
    uint8_t localIp[4] = {0};
    getInterfaceMac(ifName,localMac);
    getInterfaceIp(ifName,localIp);
    */
    // Get router address
    uint8_t routerMac[6] = {0};
    uint8_t routerIp[4] = {192,168,1,1};
    Arp_t arp;
    arp.getMac(ifname,routerIp,routerMac);
    printRaw(routerMac,ARP_HARDWARE_LEN);
    // Get target address
    uint8_t targetMac[6] = {0};
    uint8_t targetIp[4] = {192,168,1,44};
    arp.restore();
    arp.getMac(ifname,targetIp,targetMac);
    printRaw(targetMac,ARP_HARDWARE_LEN);
    return 0;
}