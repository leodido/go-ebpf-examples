package main

import (
	"fmt"
	"os"

	bpflib "github.com/iovisor/gobpf/bcc"
	"github.com/iovisor/gobpf/pkg/tracepipe"
)

import "C"

const source string = `
#include "elf/include/bpf_helpers.h"

int trace_clone(void *ctx)
{
u64 id = bpf_get_current_pid_tgid();
u32 uid = bpf_get_current_uid_gid();
u32 pid = id >> 32; // PID is the higher part
u32 tid = id;       // Cast to get the lower part
bpf_trace_printk("pid<%d> uid<%d> tid<%d> hello clone\\n", pid, uid, tid);
return 0;
}
`

func main() {
	cflags := []string{}
	m := bpflib.NewModule(source, cflags)
	defer m.Close()

	syscallName := bpflib.GetSyscallFnName("clone")
	fmt.Printf("Say hello at each %q syscall ...\n", syscallName)

	pipe, err := tracepipe.New()
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to get trace pipe: %s\n", err)
		os.Exit(1)
	}
	defer pipe.Close()

	kprobeFd, err := m.LoadKprobe("trace_clone")
	if err != nil {
		fmt.Fprintf(os.Stderr, "unable to load kprobe: %s\n", err)
		os.Exit(1)
	}

	// -1 -> use the default according to the kernel kprobe documentation
	if err := m.AttachKprobe(syscallName, kprobeFd, -1); err != nil {
		fmt.Fprintf(os.Stderr, "unable to attach kprobe: %s\n", err)
		os.Exit(1)
	}

	evtCh, errCh := pipe.Channel()
	for {
		select {
		case evt := <-evtCh:
			fmt.Println(evt)
		case err := <-errCh:
			fmt.Println(err)
		}
	}
}
