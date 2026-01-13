#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dns.h"
#include "p2p.h"

// DNS Header Structure
struct dns_header {
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
};

// Function to format hostname to DNS QNAME format (e.g., "google.com" -> "\x06google\x03com\x00")
static void format_dns_name(uint8_t *dest, const char *host) {
    int lock = 0;
    strcat((char*)dest, ".");
    strcat((char*)dest, host);
    for(int i = 0; i < (int)strlen((char*)dest); i++) {
        if(dest[i] == '.') {
            dest[i] = i - lock;
            lock = i + 1;
        }
    }
    dest[strlen((char*)dest)] = 0x00;
}

int dns_resolve_txt(const char *domain_name) {
    if (!domain_name) return -1;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return -1;

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_SERVER_PORT);
    dest.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

    struct timeval tv;
    tv.tv_sec = 2; // 2s timeout
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    // Build Query
    uint8_t buf[512];
    memset(buf, 0, 512);

    struct dns_header *dns = (struct dns_header *)&buf;
    dns->id = htons(0x1337);
    dns->flags = htons(0x0100); // Standard Query, Recursion Desired
    dns->q_count = htons(1);
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    uint8_t *qname = (uint8_t *)&buf[sizeof(struct dns_header)];
    format_dns_name(qname, domain_name);

    struct {
        uint16_t qtype;
        uint16_t qclass;
    } *qinfo;
    
    qinfo = (void *)&buf[sizeof(struct dns_header) + (strlen((const char*)qname) + 1)];
    qinfo->qtype = htons(16); // TXT Record
    qinfo->qclass = htons(1); // IN

    int packet_len = sizeof(struct dns_header) + (strlen((const char*)qname) + 1) + sizeof(*qinfo);

    // Send Query
    if (sendto(sock, buf, packet_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
        close(sock);
        return -1;
    }

    // Receive Response
    socklen_t dest_len = sizeof(dest);
    ssize_t len = recvfrom(sock, buf, 512, 0, (struct sockaddr *)&dest, &dest_len);
    if (len < (ssize_t)sizeof(struct dns_header)) {
        close(sock);
        return -1;
    }

    // Parse Response (Very minimal parser)
    // Skip Header
    uint8_t *reader = &buf[sizeof(struct dns_header)];
    
    // Skip Question Section (Name + Type(2) + Class(2))
    // Name is variable length. Loop until 0x00
    while (*reader != 0) reader++; 
    reader++; // Skip 0x00
    reader += 4; // Skip QTYPE + QCLASS

    // Now at Answer Section
    int ans_count = ntohs(dns->ans_count);
    for (int i = 0; i < ans_count; i++) {
        if (reader >= buf + len) break;

        // Name: If starts with 0xC0, it's a pointer (compression)
        if ((*reader & 0xC0) == 0xC0) {
            reader += 2; 
        } else {
             while (*reader != 0) reader++; 
             reader++;
        }

        // Type (2), Class (2), TTL (4), DataLen (2)
        uint16_t type = ntohs(*(uint16_t*)reader);
        reader += 2; // Type
        reader += 2; // Class
        reader += 4; // TTL
        uint16_t data_len = ntohs(*(uint16_t*)reader);
        reader += 2; // DataLen

        if (type == 16) { // TXT
            // TXT RDATA: [Len byte] [String] ...
            // Usually first byte is length of first string
            if (data_len > 0) {
                uint8_t txt_len = *reader;
                reader++; // Move past length byte
                
                // Safety check
                if (txt_len > 0 && (reader + txt_len <= buf + len)) {
                    // We found our TXT string!
                    // Format expectation: "ip:port;ip:port"
                    char txt_content[256];
                    if (txt_len > 255) txt_len = 255;
                    memcpy(txt_content, reader, txt_len);
                    txt_content[txt_len] = '\0';
                    
                    // Parse Addresses
                    char *token = strtok(txt_content, ";");
                    while (token != NULL) {
                       char *colon = strchr(token, ':');
                       if (colon) {
                           *colon = '\0';
                           char *ip_str = token;
                           char *port_str = colon + 1;
                           uint32_t ip = inet_addr(ip_str);
                           uint16_t port = htons(atoi(port_str));
                           if (ip != INADDR_NONE && port > 0) {
                               p2p_add_neighbor(ip, port);
                           }
                       }
                       token = strtok(NULL, ";");
                    }
                }
                reader += (data_len - 1); // Advance rest of data (if any multi-string)
            } else {
                reader += data_len;
            }
        } else {
            // Skip non-TXT Data
            reader += data_len;
        }
    }

    close(sock);
    return 0;
}
