//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

typedef enum {
    EVENT_TYPE_EXEC = 0,
    EVENT_TYPE_CONNECT = 1,
} eventTypeConn;

struct event {
    __u32 type;
    __u32 pid;
    __u32 uid;
    __u32 ppid;
    char comm[16];
    __u32 daddr;
    __u16 dport;
    __u16 _pad; //2-bytes padding to make the struct a multiple of 4
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

    e->type = EVENT_TYPE_EXEC;

    // Extract TGID (user-space PID) from the upper 32 bits of pid_tgid
    e->pid = bpf_get_current_pid_tgid() >> 32;

    e->uid = (__u32)bpf_get_current_uid_gid();

    e->ppid = p->real_parent->tgid;

    e->daddr = 0;
    e->dport = 0;

    // Read the executable name of the current process
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(handle_tcp_connect, struct sock *sk, struct sockaddr *uaddr) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    e->type = EVENT_TYPE_CONNECT;

    // Extract TGID (user-space PID) from the upper 32 bits of pid_tgid
    e->pid = bpf_get_current_pid_tgid() >> 32;

    e->uid = (__u32)bpf_get_current_uid_gid();

    e->ppid = 0;

    struct sockaddr_in *usin = (struct sockaddr_in *)uaddr;

    bpf_probe_read_kernel(&e->daddr, sizeof(e->daddr), &usin->sin_addr.s_addr);
    bpf_probe_read_kernel(&e->dport, sizeof(e->dport), &usin->sin_port);

    // Read the executable name of the current process
    bpf_get_current_comm(&e->comm, sizeof(e->comm));    

    bpf_ringbuf_submit(e, 0);
    return 0;
}