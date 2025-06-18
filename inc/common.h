#ifndef NET_COMMON_H
#define NET_COMMON_H

#include <stdint.h>
#include <cstring>

#include <sys/ioctl.h> // ioctl
#include <sys/socket.h> // socket
#include <net/if.h>
#include <arpa/inet.h> // inet_pton
#include <unistd.h> // close

// Get interface protocol address
int getInterfaceIp(char* ifName,uint8_t* ip){
    int fd = socket(AF_INET,SOCK_STREAM,0);
    ifreq ifr = {0};
    strcpy(ifr.ifr_ifrn.ifrn_name,ifName);
    ioctl(fd,SIOCGIFADDR,&ifr);
    memcpy(ip,&ifr.ifr_ifru.ifru_addr.sa_data[2],4);
    close(fd);
    return 0;
}
// Get interface netmask
int getInterfaceNetmask(char* ifName,uint8_t* msk){
    int fd = socket(AF_INET,SOCK_STREAM,0);
    ifreq ifr = {0};
    strcpy(ifr.ifr_ifrn.ifrn_name,ifName);
    ioctl(fd,SIOCGIFNETMASK,&ifr);
    memcpy(msk,&ifr.ifr_ifru.ifru_addr.sa_data[2],4);
    close(fd);
    return 0;
}
// Get interface hardware address
int getInterfaceMac(char* ifName,uint8_t* mac){
    int fd = socket(AF_INET,SOCK_STREAM,0);
    ifreq ifr = {0};
    strcpy(ifr.ifr_ifrn.ifrn_name,ifName);
    ioctl(fd,SIOCGIFHWADDR,&ifr);
    memcpy(mac,&ifr.ifr_ifru.ifru_addr.sa_data[0],6);
    close(fd);
    return 0;
}
// Fill sockaddr_in struct
int fillSockaddr(sockaddr_in* addr,char* ip,uint16_t port){
    addr->sin_family = AF_INET;
    inet_pton(AF_INET,ip,&addr->sin_addr.s_addr);
    addr->sin_port = htons(port);
    return 0;
}
// Parse sockaddr_in struct
int parseSockaddr(sockaddr_in* addr,char* ip,uint16_t* port){
    *port = ntohs(addr->sin_port);
    inet_ntop(AF_INET,&addr->sin_addr.s_addr,ip,sizeof(sockaddr_in));
    return 0;
}
// Convert string with IPv4 address into array
int ip2arr(char* ipStr,uint8_t* ipArr){
    int arr[4] = {0};
    sscanf(ipStr,"%i.%i.%i.%i",&arr[0],&arr[1],&arr[2],&arr[3]);
    ipArr[0] = (uint8_t)arr[0];
    ipArr[1] = (uint8_t)arr[1];
    ipArr[2] = (uint8_t)arr[2];
    ipArr[3] = (uint8_t)arr[3];
    return 0;
}
// Print packet content in hex format
int printRaw(uint8_t* data, uint64_t dataLen){
    uint64_t i = 0;
    while(i<dataLen){
        printf("%02x ",data[i]);
        i++;
        if(i % 8 == 4)
            printf(" ");
        if(i % 8 == 0)
            printf("\n");
    }
    if(i % 8 != 0)
        printf("\n");
    return 0;
}
// Fill sockaddr_ll struct for send data
int fillDestAddr(sockaddr_ll* addr,char* ifName,uint8_t* destMac,uint16_t protocol){
    addr->sll_family = AF_PACKET;
    addr->sll_ifindex = if_nametoindex(ifName);
    addr->sll_protocol = htons(protocol);
    addr->sll_halen = 6;
    memcpy(addr->sll_addr,destMac,6);
    return 0;
}
// Fill sockaddr_ll struct for binding socket
int fillBindAddr(sockaddr_ll* addr,char* ifName,uint16_t protocol){
    addr->sll_family = AF_PACKET;
    addr->sll_ifindex = if_nametoindex(ifName);
    addr->sll_protocol = htons(protocol);
    return 0;
}
#endif // NET_COMMON_H