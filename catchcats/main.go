package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/signal"
	"strconv"

	bpf "github.com/iovisor/gobpf/bcc"
)

const source string = `
#include <uapi/linux/ptrace.h>

#include "elf/include/bpf_helpers.h"

typedef struct {
	u32 pid;
	u32 uid;
	u32 tid;
	char str[80];
} userspace_event_t;

BPF_PERF_OUTPUT(userspace_events);

int get_return_value(struct pt_regs *ctx) {
	if (!PT_REGS_RC(ctx))
		return 0;

	u64 id = bpf_get_current_pid_tgid();
	u32 uid = bpf_get_current_uid_gid();
	userspace_event_t evt = {
		.pid = id >> 32,
		.tid = id,
		.uid = uid,
	};

	int ret = bpf_probe_read(&evt.str, sizeof(evt.str), (void *)PT_REGS_RC(ctx));
	// https://github.com/iovisor/bcc/issues/2534
	bpf_trace_printk("bpf_probe_read() return: %d\\n", ret);
	bpf_trace_printk("bpf_probe_read() result: %s\\n", evt.str);

	userspace_events.perf_submit(ctx, &evt, sizeof(evt));
	return 0;
}
`

type userspaceEvent struct {
	Pid uint32
	Uid uint32
	Tid uint32
	Str [80]byte
}

func main() {
	if len(os.Args) < 1 {
		fmt.Fprintf(os.Stderr, "missing PID")
		os.Exit(1)
	}
	m := bpf.NewModule(source, []string{})
	defer m.Close()

	uretprobe, err := m.LoadUprobe("get_return_value")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load get_return_value: %s\n", err)
		os.Exit(1)
	}

	pid, err := strconv.Atoi(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "malformed PID: %s\n", os.Args[1])
		os.Exit(1)
	}

	// proc/pid/exe
	err = m.AttachUretprobe("/caturday", "main.counterValue", uretprobe, pid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to attach get_return_value: %s\n", err)
		os.Exit(1)
	}

	table := bpf.NewTable(m.TableId("userspace_events"), m)

	channel := make(chan []byte)

	perfMap, err := bpf.InitPerfMap(table, channel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to init perf map: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill)

	fmt.Printf("%10s\t%10s\t%10s\t%s\n", "PID", "UID", "TID", "COUNT")
	go func() {
		var event userspaceEvent
		for {
			data := <-channel
			err := binary.Read(bytes.NewBuffer(data), binary.LittleEndian, &event)

			if err != nil {
				fmt.Printf("failed to decode received data: %s\n", err)
				continue
			}
			comm := string(event.Str[:bytes.IndexByte(event.Str[:], 0)])
			// fmt.Println(event.Str[:])
			fmt.Printf("%10d\t%10d\t%10d\t%s\n", event.Pid, event.Uid, event.Tid, comm)
		}
	}()

	perfMap.Start()
	<-sig
	perfMap.Stop()
}
