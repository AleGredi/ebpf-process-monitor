//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
    __u32 pid;
    char comm[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("tp_btf/sched_process_exec")
int BPF_PROG(handle_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    // Extract TGID (user-space PID) from the upper 32 bits of pid_tgid
    e->pid = bpf_get_current_pid_tgid() >> 32;

    // Read the executable name of the current process
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
