#ifndef NET_ARP_H
#define NET_ARP_H

#include <stdint.h>

#include <sys/socket.h> // socket
#include <linux/if_packet.h> // sockaddr_ll
#include <net/ethernet.h> // ETH_P_IP
#include <arpa/inet.h> // inet_pton
#include <unistd.h> // close

#include <common.h>

#define ARP_PROTO_LEN 4
#define ARP_HARDWARE_LEN 6
#define ARP_MSG_LEN 28

class Arp_t{
public:
    uint8_t buffer[ARP_MSG_LEN] = {0};
    uint8_t* oper = &buffer[7];
    uint8_t* sha = &buffer[8];
    uint8_t* spa = &buffer[14];
    uint8_t* tha = &buffer[18];
    uint8_t* tpa = &buffer[24];
    Arp_t(){
        buffer[1] = 1; // HTYPE - Ethernet
        buffer[2] = 8; // PROTO - IP
        buffer[4] = ARP_HARDWARE_LEN; // Hardware len - 6
        buffer[5] = ARP_PROTO_LEN; // Protocol len - 4
    }
    uint8_t check(){
        if((buffer[1] != 1) or (buffer[2] != 8) or (buffer[5] != ARP_PROTO_LEN))
            return 1; // Not IPv4 ARP
        return 0;
    }
    uint8_t restore(){
        buffer[1] = 1; // HTYPE - Ethernet
        buffer[2] = 8; // PROTO - IP
        buffer[4] = ARP_HARDWARE_LEN; // Hardware len - 6
        buffer[5] = ARP_PROTO_LEN; // Protocol len - 4
        return 0;
    }
    uint8_t getMac(char* ifname,uint8_t* ip,uint8_t* mac);
};

uint8_t Arp_t::getMac(char* ifname,uint8_t* ip,uint8_t* mac){
    // Create ARP socket
    int sockArp = socket(AF_PACKET,SOCK_DGRAM,htons(ETH_P_ARP));
    if(sockArp < 0)
        return 1;
    // Get interface addresses
    uint8_t localMac[6] = {0};
    uint8_t localIp[4] = {0};
    getInterfaceMac(ifname,localMac);
    getInterfaceIp(ifname,localIp);
    // Fill broadcast address
    uint8_t broadcastMac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
    sockaddr_ll broadcastAddr = {0};
    fillDestAddr(&broadcastAddr,ifname,broadcastMac,ETH_P_ARP);
    // Create packet
    memcpy(sha,localMac,ARP_HARDWARE_LEN);
    memcpy(spa,localIp,ARP_PROTO_LEN);
    memcpy(tpa,ip,ARP_PROTO_LEN);
    *oper = 1;
    // Send ARP packet
    sendto(sockArp,buffer,ARP_MSG_LEN,0,(sockaddr*)&broadcastAddr,sizeof(broadcastAddr));
    while(1){
        // Receive answer and check data
        uint64_t dataLen = recvfrom(sockArp,buffer,ARP_MSG_LEN,0,NULL,NULL);
        if(check() == 0){
            int ipcmp = memcmp(spa,ip,ARP_PROTO_LEN);
            if((ipcmp == 0) and (*oper == 2)){
                memcpy(mac,sha,ARP_HARDWARE_LEN);
                break;
            }
        }
    }
    close(sockArp);
    return 0;
}

#endif // NET_ARP_H