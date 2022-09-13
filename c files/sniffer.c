#include "../h files/sniffer.h"
#include "../h files/colors.h"


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int sock;
BYTE buffer[MAX_SIZE];
ssize_t buff_size;

int Initialize(char* interface){
    sock = socket(AF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
    setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, interface, strlen(interface));

    return sock;
}

void Sniff(char* interface) {
    int sock = Initialize(interface);
    struct ethhdr* eth_header = { 0 };
    struct iphdr* ip_header = { 0 };
    struct in_addr addr = { 0 };
    struct udphdr* udp_header = { 0 };
    struct tcphdr* tcp_header = { 0 };
    struct icmphdr* icmp_header = { 0 };


    uint16_t src_port = { 0 };
    uint16_t dst_port = { 0 };
    uint8_t ttl = { 0 };
    
    char* proto_name = NULL;
    char src_ip[16] = { 0 };
    char d_ip[16] = { 0 }; 

    unsigned long bytes_counter = 0;

    while(1) {
        proto_name = NULL;
        bytes_counter = 0;

        buff_size = recvfrom(sock,buffer, MAX_SIZE, 0,NULL,NULL);
        if(buff_size == -1){
            continue;
        }
        eth_header = (struct ethhdr*) buffer;
    
        if(eth_header->h_proto != IP_PROTO) {
            continue;
        }
        ip_header = (struct iphdr*)(buffer + sizeof(struct ethhdr));
         
        ttl = ip_header->ttl;
        addr.s_addr = ip_header->saddr;
        strcpy(src_ip,inet_ntoa(addr));


        addr.s_addr = ip_header->daddr;
        strcpy(d_ip,inet_ntoa(addr));

        if(ip_header->protocol == UDP_PROTO){
            proto_name = "UDP";
            udp_header = (struct udphdr*)(buffer + sizeof(struct iphdr) + sizeof(struct ethhdr));
            bytes_counter += sizeof(struct udphdr);


            src_port = udp_header->uh_sport;
            dst_port = udp_header->uh_dport;
        } 
        else if(ip_header->protocol == TCP_PROTO) {
            proto_name = "TCP";
            tcp_header= (struct tcphdr*)(buffer + sizeof(struct iphdr) + sizeof(struct ethhdr));
            bytes_counter += sizeof(struct tcphdr);
            
            

            src_port = tcp_header->th_sport;
            dst_port = tcp_header->th_dport;
        }
        else if(ip_header->protocol == ICMP_PROTO){
            proto_name = "ICMP";

            icmp_header = (struct icmphdr*)(buffer + sizeof(struct iphdr) + sizeof(struct ethhdr));
        }
        


        GREEN();
        printf("***************************** - %s PACKET - **********************************\n",proto_name);
        CYAN();
        printf("ETHERNET HEADER:\n");
        printf("\t| - Source mac: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n", eth_header->h_source[0],eth_header->h_source[1], eth_header->h_source[2], eth_header->h_source[3], eth_header->h_source[4], eth_header->h_source[5]);
        printf("\t| - Dest mac: %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n\n", eth_header->h_dest[0],eth_header->h_dest[1], eth_header->h_dest[2], eth_header->h_dest[3], eth_header->h_dest[4], eth_header->h_dest[5]);

        printf("\n");
        YELLOW();
        printf("IP HEADER:\n");
        printf("\t| - IP SOURCE: %s\n",src_ip);
        printf("\t| - IP DEST: %s\n", d_ip);
        printf("\t| - TTL: %u\n\n",ttl);

        PURPLE();
        if(strcmp(proto_name,"ICMP") != 0){
            printf("%s HEADER:\n", proto_name);
            printf("\t| - SOURCE PORT: %hu\n", src_ip);
            printf("\t| - DEST PORT: %hu\n", dst_port);
        }

        GREEN();
        printf("*******************************************************************************\n\n\n");
    }

    close(sock);
}
