#include "obfuscate.h"

void deobfuscate(char *str, size_t len) {
    for (size_t i = 0; i < len; i++) {
        str[i] ^= XOR_KEY;
    }
}
