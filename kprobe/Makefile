CLANG = clang

CFLAGS = -O2 -target bpf

KPROBE = kprobe

all: 

kprobe: prepare vmlinux.h bpf_helpers.h generate
	go build -o $(KPROBE) main.go bpf_bpfel.go

prepare:
	export BPF_CLANG=clang

generate:
	go generate

vmlinux.h: 
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

bpf_helpers.h: bpf_helper_defs.h
	cp /usr/include/bpf/bpf_helpers.h ./bpf_helpers.h

bpf_helper_defs.h:
	cp /usr/include/bpf/bpf_helper_defs.h ./bpf_helper_defs.h

clean:
	rm -f bpf_helper_defs.h bpf_helpers.h vmlinux.h sock1.kern.o bpf_bpfel.* bpf_bpfeb.* $(KPROBE)