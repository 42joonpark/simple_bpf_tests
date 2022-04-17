//go:build linux
// +build linux

// This program demonstrates attaching an eBPF program to a kernel symbol.
// The eBPF program will be attached to the start of the sys_execve
// kernel function and prints out the number of times it has been called
// every second.
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc $BPF_CLANG -cflags $BPF_CFLAGS -type event bpf program.bpf.c -- -I../headers

func main() {

	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatal(err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	enter_accept_hook, err := link.Tracepoint("syscalls", "sys_enter_accept", objs.SysEnterAccept)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer enter_accept_hook.Close()

	exit_accept_hook, err := link.Tracepoint("syscalls", "sys_exit_accept", objs.SysExitAccept)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer exit_accept_hook.Close()

	enter_close_hook, err := link.Tracepoint("syscalls", "sys_enter_close", objs.SysEnterClose)
	if err != nil {
		log.Fatalf("opening tracepoint: %s", err)
	}
	defer enter_close_hook.Close()

	// Read loop reporting the total amount of times the kernel
	// function was entered, once per second.
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	log.Println("Waiting for events..")

	for range ticker.C {
		fmt.Println("Running....")
	}

	// const mapKey uint32 = 0
	// const mapKey2 uint32 = 0

	// fmt.Printf("bpfObject: \n%+v\n", objs)
	// for range ticker.C {
	// 	// var value uint64
	// 	var value bpfEvent
	// 	var value2 uint64
	// 	// if err := objs.Events.Lookup(mapKey, &value); err != nil {
	// 	if err := objs.bpfMaps.Events.Lookup(mapKey, &value); err != nil {
	// 		log.Fatalf("reading map: %v", err)
	// 	}
	// 	log.Printf("%s called %v %v %v %v\n", fn, value.Saddr, value.Daddr, value.Sport, value.Dport)
	// 	if err := objs.bpfMaps.KprobeMap.Lookup(mapKey2, &value2); err != nil {
	// 		log.Fatal("reading map: %v", err)
	// 	}
	// 	log.Printf("%s called %d times\n", fn2, value2)
	// }
}
