#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include "proxy.h"
#include "mqtt_parser.h"

// Authenticated Topic (Pre-shared Key)
#define AUTH_TOPIC "dev/sys/log"

static Subscriber subscribers[MAX_SUBSCRIBERS];

int proxy_init(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PROXY_LISTEN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("Bind failed");
        close(sock);
        return -1;
    }

    if (listen(sock, 1024) < 0) { 
        perror("Listen failed");
        close(sock);
        return -1;
    }
    
    // Non-blocking
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    // Init Subscribers
    for(int i=0; i<MAX_SUBSCRIBERS; i++) {
        subscribers[i].fd = -1;
        subscribers[i].active = false;
    }

    return sock;
}

void proxy_handle_new_conn(int listener_sock) {
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    int client_sock = accept(listener_sock, (struct sockaddr *)&client_addr, &addr_len);
    if (client_sock < 0) return;

    // Set Non-blocking
    int flags = fcntl(client_sock, F_GETFL, 0);
    fcntl(client_sock, F_SETFL, flags | O_NONBLOCK);

    // Add to Subscriber List
    int added = 0;
    for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
        if (!subscribers[i].active) {
            subscribers[i].fd = client_sock;
            subscribers[i].active = true;
            subscribers[i].last_heartbeat = time(NULL);
            added = 1;
            // printf("[Proxy] New Subscriber: %d\n", client_sock);
            break;
        }
    }

    if (!added) {
        close(client_sock); // Full
    }
}

// Helper to encode MQTT Var Length
static void encode_var_length(size_t len, uint8_t *buf, size_t *out_len) {
    size_t i = 0;
    do {
        uint8_t byte = len % 128;
        len /= 128;
        if (len > 0) byte |= 128;
        buf[i++] = byte;
    } while (len > 0);
    *out_len = i;
}

void proxy_broadcast(const uint8_t *payload, size_t len) {
    // Construct MQTT PUBLISH Packet
    // [0x30] [Remaining Len] [Topic Len] [Topic] [Payload]
    // Topic: "cmd/broadcast"
    const char *topic = "cmd/broadcast";
    size_t topic_len = strlen(topic);
    
    uint8_t header[128];
    // size_t h_len = 0;
    
    header[0] = 0x30; // PUBLISH, QoS 0
    
    // Remaining Length = 2 (Topic Len) + Topic + Payload
    size_t rem_len = 2 + topic_len + len;
    size_t var_len_bytes = 0;
    
    uint8_t var_len_buf[4];
    encode_var_length(rem_len, var_len_buf, &var_len_bytes);
    
    // Send to all subscribers
    for (int i = 0; i < MAX_SUBSCRIBERS; i++) {
        if (subscribers[i].active) {
            // Write Header
            send(subscribers[i].fd, &header[0], 1, MSG_NOSIGNAL);
            send(subscribers[i].fd, var_len_buf, var_len_bytes, MSG_NOSIGNAL);
            
            // Write Topic
            uint16_t tlen_be = htons(topic_len);
            send(subscribers[i].fd, &tlen_be, 2, MSG_NOSIGNAL);
            send(subscribers[i].fd, topic, topic_len, MSG_NOSIGNAL);
            
            // Write Payload
            if (send(subscribers[i].fd, payload, len, MSG_NOSIGNAL) < 0) {
                // Error, disconnect
                close(subscribers[i].fd);
                subscribers[i].active = false;
            }
        }
    }
}

void proxy_poll(void) {
    // Basic cleanup or keepalive check
    // Not implemented fully for simplicity, but hook exists.
}
