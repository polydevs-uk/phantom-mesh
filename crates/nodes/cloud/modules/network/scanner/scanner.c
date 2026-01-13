#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>
#include <errno.h>

#include "scanner.h"

// Pseudo Header for Checksum Calculation
struct pseudo_header {
    uint32_t source_address;
    uint32_t dest_address;
    uint8_t placeholder;
    uint8_t protocol;
    uint16_t tcp_length;
};

static int raw_sock = -1;
static uint16_t target_port = 23; // Telnet default

// Checksum Calculator
static unsigned short csum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

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

bool scanner_init(void) {
    // Create Raw Socket
    // Requires ROOT privileges
    raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_sock < 0) {
        perror("Socket creation failed");
        return false;
    }

    // Tell kernel we provide the IP header
    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("Error setting IP_HDRINCL");
        close(raw_sock);
        return false;
    }

    srand(time(NULL));
    return true;
}

static uint32_t get_random_ip() {
    uint32_t ip;
    do {
        ip = rand();
        // Skip 127.x.x.x (Loopback)
        if ((ip & 0xFF) == 127) continue;
        // Skip 10.x.x.x (Private)
        if ((ip & 0xFF) == 10) continue;
        // Skip 192.168.x.x (Private)
        if ((ip & 0xFFFF) == 0xA8C0) continue; 
        // Skip 172.16.x.x-172.31.x.x (Private) - simplified check
        if ((ip & 0xFF) == 172 && ((ip >> 8) & 0xF0) == 16) continue;
        
        break; 
    } while (1);
    return ip;
}

void scanner_run_batch(void) {
    if (raw_sock < 0) return;

    // Send a burst of SYN packets
    char packet[4096];
    struct ip *iph = (struct ip *)packet;
    struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct ip));
    struct pseudo_header psh;

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;

    // Random destination
    uint32_t dest_ip = get_random_ip();
    sin.sin_addr.s_addr = dest_ip;
    
    // Fake Source IP (Spoofing)
    uint32_t source_ip = get_random_ip(); // Spoof random source for now (or use real if behind NAT)

    memset(packet, 0, 4096);


    iph->ip_hl = 5;
    iph->ip_v = 4;
    iph->ip_tos = 0;
    iph->ip_len = sizeof(struct ip) + sizeof(struct tcphdr); // BSD ip_len is host byte order? usually network
    iph->ip_id = htonl(54321);
    iph->ip_off = 0;
    iph->ip_ttl = 255;
    iph->ip_p = IPPROTO_TCP;
    iph->ip_sum = 0;
    iph->ip_src.s_addr = source_ip;
    iph->ip_dst.s_addr = dest_ip;

    // IP Checksum
    iph->ip_sum = csum((unsigned short *)packet, iph->ip_len);

    // TCP Header (BSD style)
    tcph->th_sport = htons(12345);
    tcph->th_dport = htons(target_port);
    tcph->th_seq = 0;
    tcph->th_ack = 0;
    tcph->th_off = 5;
    tcph->th_flags = TH_SYN;
    tcph->th_win = htons(5840);
    tcph->th_sum = 0;
    tcph->th_urp = 0;

    // TCP Checksum Calculation
    psh.source_address = source_ip;
    psh.dest_address = dest_ip;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));

    int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
    char *pseudogram = malloc(psize);
    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));

    tcph->th_sum = csum((unsigned short *)pseudogram, psize);
    free(pseudogram);

    // Send Packet
    if (sendto(raw_sock, packet, iph->ip_len, 0, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        // perror("Sendto failed");
    } else {
        // printf("Sent SYN to %s\n", inet_ntoa(sin.sin_addr));
    }
}

void scanner_info(void) {
    if (raw_sock >= 0) close(raw_sock);
}
