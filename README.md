# ebpf-process-monitor

A Linux process observability tool built with **eBPF (CO-RE)** and **Go** (`cilium/ebpf`).

It hooks into the Linux kernel tracepoint subsystem to capture process execution events in real time using a lockless BPF Ring Buffer.

## Architecture

```
Kernel Space (eBPF)                           User Space (Go)
+--------------------------------+            +-----------------------------+
| sched_process_exec tracepoint  |            | cilium/ebpf loader          |
|               |                |            | - Loads & attaches probe    |
|               v                |            +-----------------------------+
| eBPF probe (handle_exec)       |                           |
| - Extracts TGID & binary name  |                           v
|               |                |            +-----------------------------+
|               v                |            | Ring buffer consumer        |
| BPF Ring Buffer map (256 KB)   | ---------> | - Reads & decodes events    |
| (BPF_MAP_TYPE_RINGBUF)         |            | - Formatted stdout stream   |
+--------------------------------+            +-----------------------------+
```

## Prerequisites

- Linux kernel >= 5.8 with BTF support (`/sys/kernel/btf/vmlinux`)
- Go >= 1.20
- Clang / LLVM and libbpf development headers

On Ubuntu/Debian:
```bash
sudo apt install -y golang-go clang llvm libbpf-dev
```

## Build & Run

```bash
# 1. Compile eBPF C code and generate Go bindings
cd cmd/monitor
go generate

# 2. Build the Go binary
go build -o monitor

# 3. Run with privileges
sudo ./monitor
```

## Example Output

```text
🚀 Process monitor started! Listening for execution events...
Press Ctrl+C to stop.
----------------------------------------------------------------
[MONITOR] 🎯 Exec: PID: 45123   | COMM: ls
[MONITOR] 🎯 Exec: PID: 45124   | COMM: curl
[MONITOR] 🎯 Exec: PID: 45130   | COMM: git
```
