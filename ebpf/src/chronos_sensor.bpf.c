/*
 * CHRONOS-FL eBPF Sensor Probes (CO-RE BPF)
 * Captures process activity (execve, fork, clone), file activity (create, delete),
 * network activity (connect, bind, accept), and privilege activity (sudo/setuid).
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "../include/chronos_events.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int tracepoint_syscalls_sys_enter_execve(struct trace_event_raw_sys_enter* ctx) {
    struct chronos_event *evt;
    
    evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid();
    evt->type = EVT_EXECVE;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tracepoint_syscalls_sys_enter_connect(struct trace_event_raw_sys_enter* ctx) {
    struct chronos_event *evt;

    evt = bpf_ringbuf_reserve(&ringbuf, sizeof(*evt), 0);
    if (!evt)
        return 0;

    evt->timestamp_ns = bpf_ktime_get_ns();
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->uid = bpf_get_current_uid_gid();
    evt->type = EVT_CONNECT;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    bpf_ringbuf_submit(evt, 0);
    return 0;
}
