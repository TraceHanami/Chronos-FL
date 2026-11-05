#ifndef CHRONOS_EVENTS_H
#define CHRONOS_EVENTS_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 256

enum chronos_event_type {
    EVT_EXECVE  = 1,
    EVT_FORK    = 2,
    EVT_CLONE   = 3,
    EVT_CREATE  = 4,
    EVT_DELETE  = 5,
    EVT_RENAME  = 6,
    EVT_CONNECT = 7,
    EVT_BIND    = 8,
    EVT_ACCEPT  = 9,
    EVT_SUDO    = 10,
    EVT_SETUID  = 11,
    EVT_CAPABILITY = 12,
    EVT_ANTI_FORENSIC = 13,
};

struct chronos_event {
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tid;
    __u32 ppid;
    __u32 uid;
    __u32 gid;
    __u8  type;              /* enum chronos_event_type */
    char  comm[TASK_COMM_LEN];
    char  target_path[MAX_FILENAME_LEN];

    /* network fields */
    __u32 saddr;
    __u32 daddr;
    __u16 sport;
    __u16 dport;
    __u8  protocol;

    __s32 ret;
};

#endif /* CHRONOS_EVENTS_H */
