#ifndef __LOADED__
#define __LOADED__

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <net/ethernet.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip.h>

typedef char BYTE;

#define MAX_SIZE 65536
#define SO_BINDTODEVICE 25
#define IP_PROTO 8

#define UDP_PROTO 17 
#define TCP_PROTO 6
#define ICMP_PROTO 1 


void Sniff(char* interface);


#endif