build: bin/countpackets bin/helloworld

bin/countpackets: countpackets/main.go pkts.o
	@mkdir -p bin
	@unset GOFLAGS
	go build -o $@ $<

bin/helloworld: helloworld/main.go vendor
	@mkdir -p bin
	@# use modules in vendor to get the iovisor/gobpf#202 fix
	GOFLAGS=-mod=vendor go build -o $@ $<

# bin/catchcats: catchcats/main.go vendor
# 	@mkdir -p bin
# 	@# use modules in vendor to get the iovisor/gobpf#202 fix
# 	GOFLAGS=-mod=vendor go build -o $@ $<

setup: elf/include/bpf_helpers.h elf/include/bpf_map.h

elf/include/bpf_helpers.h: elf/include
	@curl -s -o $@ -LO https://git.archlinux.org/linux.git/plain/tools/testing/selftests/bpf/bpf_helpers.h?h=v5.0-arch1
	@sed -i '/\/\* a helper/{:a;N;/\};/!ba};/struct bpf_map_def/d' elf/include/bpf_helpers.h

elf/include/bpf_map.h: elf/include
	@curl -s -o $@ -LO https://raw.githubusercontent.com/iovisor/gobpf/master/elf/include/bpf_map.h

elf/include:
	@mkdir -p $@

%.o: %.c elf/include/bpf_helpers.h elf/include/bpf_map.h
	clang -O2 -S -target bpf -c $< -o $@

.PHONY: vendor
vendor:
	go mod vendor
	@# fix iovisor/gobpf#202 (not in pair with a BCC's bpf_module_create_c_from_string signature)
	@# remove following as soon https://github.com/iovisor/gobpf/pull/210 is merged in
	@sed -i 's/\(bpf_module_create_c_from_string.*\))/\1, nil)/' vendor/github.com/iovisor/gobpf/bcc/module.go

clean:
	@rm -rf elf
	@rm -rf bin
	@rm -rf vendor
	@rm -rf *.o