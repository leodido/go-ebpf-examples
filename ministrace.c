#include <linux/bpf.h>

#include "elf/include/bpf_helpers.h"
#include "elf/include/bpf_map.h"

struct bpf_map_def SEC("maps/syscalls") syscallsmap = {
    .type = BPF_MAP_TYPE_QUEUE,
    .key_size = 0,
    .value_size = sizeof(int),
    .max_entries = 32,
};

SEC("tracepoint/raw_syscalls/sys_enter")
int tracepoint__raw_syscalls__sys_enter()
{
    int two = 2;
    // bpf_map_update_elem(&syscallsmap, 0, &two, 0);
    bpf_map_push_elem(&syscallsmap, &two, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";

unsigned int _version SEC("version") = 0xFFFFFFFE;