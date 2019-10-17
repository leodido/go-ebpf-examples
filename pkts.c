#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stddef.h>

#include "elf/include/bpf_helpers.h"
#include "elf/include/bpf_map.h"

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) & ((TYPE *)0)->MEMBER)
#endif

// map containing pairs <protocol number, count>
// https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
struct bpf_map_def SEC("maps/packets") countmap = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 256,
};

SEC("socket/countpackets")
int socket_prog(struct __sk_buff *skb)
{
  int proto = load_byte(skb, ETH_HLEN + offsetof(struct iphdr, protocol));
  int one = 1;
  int *el = bpf_map_lookup_elem(&countmap, &proto);
  if (el)
  {
    (*el)++;
  }
  else
  {
    el = &one;
  }
  bpf_map_update_elem(&countmap, &proto, el, BPF_ANY);
  return 0;
}

char _license[] SEC("license") = "GPL";

// this tells to the ELF loader to set the current running kernel version
unsigned int _version SEC("version") = 0xFFFFFFFE;