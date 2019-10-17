build: countpackets

countpackets: countpackets/main.go pkts.o
	@mkdir -p bin
	go build -o bin/$@ $<

setup: elf/include/bpf_helpers.h elf/include/bpf_map.h
elf/include/bpf_helpers.h: elf/include
	@curl -s -o $@ -LO https://git.archlinux.org/linux.git/plain/tools/testing/selftests/bpf/bpf_helpers.h?h=v5.0-arch1
	@sed -i '/\/\* a helper/{:a;N;/\};/!ba};/struct bpf_map_def/d' elf/include/bpf_helpers.h

elf/include/bpf_map.h: elf/include
	@curl -s -o $@ -LO https://raw.githubusercontent.com/iovisor/gobpf/master/elf/include/bpf_map.h

elf/include:
	@mkdir -p $@

pkts.o: pkts.c elf/include/bpf_helpers.h elf/include/bpf_map.h
	clang -O2 -target bpf -c $< -o $@

clean:
	@rm -rf elf
	@rm -rf *.o