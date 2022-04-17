#include "vmlinux.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

struct exit_accept4 {
	u64	_unused1;
	u64	_unused2;

	u32	ret;
};

struct enter_close {
	u64	_unused1;
	u64	_unused2;

	u64	fd;
};

struct event {
	pid_t	pid;
	u32		ret;
	int		fd;
	u64		duration_ms;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct event);
	__uint(max_entries, 10);
} time_events SEC(".maps");

const struct event *unused __attribute__((unused));

SEC("tracepoint/sys_exit_accept4")
int __sys_exit_accept4(struct exit_accept4* args)
{
	struct event info = {};
	return 0;
}

SEC("tracepoint/tcp_retransmit_skb")
int tcp_probe(struct tcp_entry* args) {
	// struct event info = {};
	struct event *valp;
	u32 key = 0;

	bpf_probe_read(&info.saddr, sizeof(info.saddr), &args->saddr);
	bpf_probe_read(&info.daddr, sizeof(info.daddr), &args->daddr);
	bpf_probe_read(&info.sport, sizeof(info.sport), &args->sport);
	bpf_probe_read(&info.dport, sizeof(info.dport), &args->dport);

	valp = bpf_map_lookup_elem(&events, &key);
	bpf_map_update_elem(&events, &key, &info, BPF_ANY);

	return 0;
}

SEC("tracepoint/sys_enter_execve")
int kprobe_execve() {
	u32 key     = 0;
	u64 initval = 1, *valp;

	valp = bpf_map_lookup_elem(&kprobe_map, &key);
	if (!valp) {
		bpf_map_update_elem(&kprobe_map, &key, &initval, BPF_ANY);
		return 0;
	}
	__sync_fetch_and_add(valp, 1);

	return 0;
}