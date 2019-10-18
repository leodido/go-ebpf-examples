package main

import (
	"fmt"
	"os"
	"path"

	bpflib "github.com/iovisor/gobpf/elf"
)

const eBPFFileName = "ministrace.o"

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

	syscallsMap := m.Map("syscalls")
	if syscallsMap == nil {
		fmt.Fprintln(os.Stderr, "unable to find `syscalls` eBPF map")
		os.Exit(1)
	}
	fmt.Println(syscallsMap)
}
