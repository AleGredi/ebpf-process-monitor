package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf monitor ../../bpf/monitor.bpf.c -- -I../../bpf -I/usr/include -D__TARGET_ARCH_x86

const (                                                                                                         
        EventTypeExec    uint32 = 0                                                                                 
        EventTypeConnect uint32 = 1                                                                                 
    )   

// Event mirrors the C struct event layout received from the kernel ring buffer.
type Event struct {
	Type  uint32
	Pid   uint32
	Uid   uint32
	Ppid  uint32
	Comm  [16]byte
	Daddr uint32
	Dport uint16
	Pad   uint16
}

func main() {
	// Allow the process to lock memory for eBPF maps
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("Failed to remove memlock limit: %v", err)
	}

	// Load pre-compiled eBPF programs and maps into the kernel
	objs := monitorObjects{}
	if err := loadMonitorObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load eBPF objects: %v", err)
	}
	defer objs.Close()

	// Attach handle_exec program to the sched_process_exec tracepoint
	tp, err := link.AttachTracing(link.TracingOptions{
		Program: objs.HandleExec,
	})
	if err != nil {
		log.Fatalf("Failed to attach tracepoint: %v", err)
	}
	defer tp.Close()

	kp, err := link.Kprobe("tcp_v4_connect", objs.HandleTcpConnect, nil)
    if err != nil {
        log.Fatalf("Failed to attach kprobe: %v", err)
    }
    defer kp.Close()

	// Open the eBPF ring buffer reader for the 'events' map
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("Failed to open ringbuf reader: %v", err)
	}
	defer rd.Close()

	// Graceful shutdown on Ctrl+C (SIGINT / SIGTERM)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("\nReceived stop signal. Cleaning up...")
		rd.Close()
	}()

	fmt.Println("🚀 Process monitor started! Listening for execution and network events...")
	fmt.Println("Press Ctrl+C to stop.")
	fmt.Println("----------------------------------------------------------------")

	var event Event
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				fmt.Println("Ring buffer closed. Exiting.")
				return
			}
			log.Printf("Error reading from ring buffer: %v", err)
			continue
		}

		// Parse the raw binary payload into our Go Event struct
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Failed to decode event: %v", err)
			continue
		}

		// Strip trailing null bytes from the command string
		commName := string(bytes.TrimRight(event.Comm[:], "\x00"))

		switch event.Type {
		case EventTypeExec:
			fmt.Printf("[MONITOR] 🎯 Exec: UID: %-5d | PID: %-7d | PPID: %-7d | COMM: %s\n", event.Uid, event.Pid, event.Ppid, commName)
		case EventTypeConnect:
			destIP := net.IPv4(byte(event.Daddr), byte(event.Daddr>>8), byte(event.Daddr>>16), byte(event.Daddr>>24))
			destPort := (event.Dport>>8) | (event.Dport<<8)
			fmt.Printf("[MONITOR] 🌐 Net:  UID: %-5d | PID: %-7d | COMM: %-15s -> %s:%d\n", event.Uid, event.Pid, commName, destIP, destPort)
		}

	}
}
