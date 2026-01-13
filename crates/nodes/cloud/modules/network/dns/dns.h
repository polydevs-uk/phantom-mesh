#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <stdbool.h>

// Default DNS Resolver (Google)
#define DNS_SERVER_IP "8.8.8.8"
#define DNS_SERVER_PORT 53

/**
 * Performs a synchronous DNS TXT query for 'domain_name'.
 * Parses the response assuming format "ip:port;ip:port;"
 * Adds valid entries to the P2P neighbor table.
 * 
 * @param domain_name The domain to query (e.g., "seeds.phantom.bot")
 * @return 0 on success, -1 on failure
 */
int dns_resolve_txt(const char *domain_name);

#endif // DNS_H
