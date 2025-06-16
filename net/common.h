#ifndef NET_COMMON_H
#define NET_COMMON_H

#include <stdint.h>
#include <cstring>

#include <sys/ioctl.h> // ioctl
#include <sys/socket.h> // socket
#include <net/if.h>
#include <unistd.h> // close


int getIp(char* ifName,uint8_t* ip){
    int fd = socket(AF_INET,SOCK_STREAM,0);
    ifreq ifr = {0};
    strcpy(ifr.ifr_ifrn.ifrn_name,ifName);
    ioctl(fd,SIOCGIFADDR,&ifr);
    memcpy(ip,&ifr.ifr_ifru.ifru_addr.sa_data[2],4);
    close(fd);
    return 0;
}

int getNetmask(char* ifName,uint8_t* msk){
    int fd = socket(AF_INET,SOCK_STREAM,0);
    ifreq ifr = {0};
    strcpy(ifr.ifr_ifrn.ifrn_name,ifName);
    ioctl(fd,SIOCGIFNETMASK,&ifr);
    memcpy(msk,&ifr.ifr_ifru.ifru_addr.sa_data[2],4);
    close(fd);
    return 0;
}

int getMac(char* ifName,uint8_t* mac){
    int fd = socket(AF_INET,SOCK_STREAM,0);
    ifreq ifr = {0};
    strcpy(ifr.ifr_ifrn.ifrn_name,ifName);
    ioctl(fd,SIOCGIFHWADDR,&ifr);
    memcpy(mac,&ifr.ifr_ifru.ifru_addr.sa_data[0],6);
    close(fd);
    return 0;
}

#endif // NET_COMMON_H