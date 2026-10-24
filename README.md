# ebpf-process-monitor

A Linux process and network observability tool built with **eBPF (CO-RE)** and **Go** (`cilium/ebpf`).

It hooks into both the Linux kernel tracepoint subsystem and socket connect functions to capture process execution and outbound TCP connection events in real time using a lockless BPF Ring Buffer.

## Architecture

```
Kernel Space (eBPF)                                  User Space (Go)
+---------------------------------------+            +-----------------------------+
| sched_process_exec (Tracepoint)       |            | cilium/ebpf loader          |
| -> handle_exec                        |            | - Loads & attaches probes   |
|    Extracts PID, UID, PPID, COMM      |            +-----------------------------+
|                                       |                           |
| tcp_v4_connect (Kprobe)               |                           v
| -> handle_tcp_connect                 |            +-----------------------------+
|    Extracts PID, UID, COMM, IP, Port  |            | Ring buffer consumer        |
|                   |                   | ---------> | - Multiplexes event types   |
|                   v                   |            | - Endianness & IP decoding  |
|      BPF Ring Buffer (256 KB)         |            | - Formatted stdout stream   |
+---------------------------------------+            +-----------------------------+
```

## Features

- **Process Execution Tracing**: Hooks `sched_process_exec` with CO-RE (`tp_btf`) to track process execution, parent PID (`PPID`), user ID (`UID`), and process name (`COMM`).
- **Outbound TCP Tracing**: Hooks `tcp_v4_connect` via Kprobe to intercept outbound IPv4 connections with destination IP and port.
- **Lockless Ring Buffer**: Zero-copy event streaming across CPU cores preserving chronological order.
- **CO-RE Portability**: Relies on BTF (`/sys/kernel/btf/vmlinux`) for run-time field relocations.

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
🚀 Process monitor started! Listening for execution and network events...
Press Ctrl+C to stop.
----------------------------------------------------------------
[MONITOR] 🎯 Exec: UID: 1000  | PID: 64570   | PPID: 44486   | COMM: ls
[MONITOR] 🎯 Exec: UID: 1000  | PID: 64605   | PPID: 10394   | COMM: curl
[MONITOR] 🌐 Net:  UID: 1000  | PID: 64605   | COMM: curl            -> 1.1.1.1:80
[MONITOR] 🌐 Net:  UID: 1000  | PID: 7028    | COMM: Socket Thread   -> 140.82.113.25:443
```
