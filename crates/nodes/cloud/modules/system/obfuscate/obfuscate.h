#ifndef OBFUSCATE_H
#define OBFUSCATE_H

#include <stddef.h>

// Simple XOR Key (Can be dynamic)
#define XOR_KEY 0x5A

// In-place deobfuscation
void deobfuscate(char *str, size_t len);

// Helper to manually scramble string during dev if needed
// (But usually we just hardcode hex arrays)

#endif
