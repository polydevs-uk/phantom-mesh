#ifndef SCANNER_H
#define SCANNER_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

// Scanner Configuration
#define SCANNER_MAX_PPS 1000 // Packets Per Second Limit (to avoid crashing router)

/**
 * Initializes the raw socket for scanning.
 * @return true on success, false on failure (e.g. no root privileges)
 */
bool scanner_init(void);

/**
 * Starts the SYN scanner loop in a non-blocking/background manner.
 * Note: In a real single-threaded bot, this would be part of the main select/poll loop
 * or called periodically. For this implementation, we'll expose a function to 
 * send a batch of SYN packets.
 */
void scanner_run_batch(void);

/**
 * Kills the scanner socket.
 */
void scanner_info(void);

#endif // SCANNER_H
