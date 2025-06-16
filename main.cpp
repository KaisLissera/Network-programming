#include <stdio.h>
#include <cstring>
#include <stdint.h>

#include <sys/socket.h> // socket
#include <unistd.h> // close

#include "net/common.h"

int main(int argc,char** argv){
    uint8_t mac[6] = {0};
    uint8_t ip[4] = {0};
    uint8_t ipMsk[4] = {0};

    getMac((char*)"eth0",mac);
    getIp((char*)"eth0",ip);
    getNetmask((char*)"eth0",ipMsk);

    printf("mac %x:%x:%x:%x:%x:%x\n",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    printf("ip  %i.%i.%i.%i\n",ip[0],ip[1],ip[2],ip[3]);
    printf("msk %i.%i.%i.%i\n",ipMsk[0],ipMsk[1],ipMsk[2],ipMsk[3]);
    return 0;
}