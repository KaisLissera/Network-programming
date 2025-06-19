#ifndef NET_PARSE_H
#define NET_PARSE_H

#include <stdint.h>
#include <cstring>

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
    //
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

#endif // NET_PARSE_H