#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define PUBKEY_LEN 32
#define SIG_LEN 64

// Verify Ed25519 Signature (Stub/Simulated for Phase 3)
// Returns true if valid
bool ed25519_verify(const uint8_t *msg, size_t msg_len, const uint8_t *sig);

#endif
