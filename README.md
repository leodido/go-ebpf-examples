# Go eBPF examples

> Experimenting eBPF with Go

## Prerequisites

These examples have been created on an Archlinux box with kernel v5.0.

The main prerequisites are:

- linux headers
- clang
- bcc ([how to install](https://github.com/iovisor/bcc/blob/master/INSTALL.md))

## Working examples

- helloworld
  - `make bin/helloworld`
  - kprobe(clone) + trace_pipe + iovisor/gobpf/bcc (helloworld/main.go)

- countpackets
  - `make bin/countpackets`
  - socket filter + map (pkts.c) + iovisor/gobpf/elf (countpackets/main.go)

- <strike>catchcats</strike>

- <strike>ministrace</strike>