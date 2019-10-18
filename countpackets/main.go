package main

import (
	"fmt"
	"os"
	"path"
	"syscall"
	"time"
	"unsafe"

	bpflib "github.com/iovisor/gobpf/elf"
	"github.com/skydive-project/skydive/common"
	"github.com/vishvananda/netlink"
)

const howlong = 10 * time.Second
const interval = 1 * time.Second

const eBPFFileName = "pkts.o"

func getBPF() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("unable to find %q eBPF file", eBPFFileName)
	}
	return path.Join(dir, eBPFFileName), nil
}

func main() {
	bpf, err := getBPF()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	m := bpflib.NewModule(bpf)
	if err := m.Load(nil); err != nil {
		fmt.Fprintf(os.Stderr, "error loading %q: %s\n", bpf, err)
		os.Exit(1)
	}

	countpacketsMap := m.Map("packets")
	if countpacketsMap == nil {
		fmt.Fprintln(os.Stderr, "unable to find `packets` eBPF map")
		os.Exit(1)
	}

	countpacketsProgram := m.SocketFilter("socket/countpackets")
	if countpacketsProgram == nil {
		fmt.Fprintln(os.Stderr, "unable to find `countpackets` socket filter eBPF program")
		os.Exit(1)
	}

	links, err := netlink.LinkList()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	for _, link := range links {
		// open a socket in the network namespace for interface
		rs, err := common.NewRawSocketInNs("/proc/1/ns/net", link.Attrs().Name, syscall.ETH_P_ALL)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if err := bpflib.AttachSocketFilter(countpacketsProgram, rs.GetFd()); err != nil {
			fmt.Fprintln(os.Stderr, "unable to attach `countpackets` socket filter eBPF program")
			os.Exit(1)
		}
	}

	tick := time.NewTicker(interval)
	quit := make(chan struct{})

	go func() {
		for {
			select {
			case <-tick.C:
				poll(m, countpacketsMap)
			case <-quit:
				fmt.Fprintln(os.Stdout, "quit")
				return
			}
		}
	}()

	time.Sleep(howlong)
	tick.Stop()
	close(quit)
	time.Sleep(time.Millisecond * 500)
}

func poll(bpf *bpflib.Module, m *bpflib.Map) {
	var err error
	var k, v, n uint64
	still := true
	for still {
		still, err = bpf.LookupNextElement(m, unsafe.Pointer(&k), unsafe.Pointer(&n), unsafe.Pointer(&v))
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			break
		}

		fmt.Println(k, v)
		k = n
	}
	fmt.Println("-----")
}
