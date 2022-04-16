#include "vmlinux.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") events = {
	.type        = BPF_MAP_TYPE_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = sizeof(u64),
	.max_entries = 1,
};

struct tcp_entry {
	u64 _unused;

	__u8 saddr[sizeof(struct sockaddr_in6)];
	__u8 daddr[sizeof(struct sockaddr_in6)];
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u32 mark;
	__u16 data_len;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 snd_cwnd;
	__u32 ssthresh;
	__u32 snd_wnd;
	__u32 srtt;
	__u32 rcv_wnd;
	__u64 sock_cookie;
};

struct event {
	__u8 saddr[sizeof(struct sockaddr_in6)];
	__u8 daddr[sizeof(struct sockaddr_in6)];
	__u16 sport;
	__u16 dport;
	/*
	__u16 family;
	__u32 mark;
	__u16 data_len;
	__u32 snd_nxt;
	__u32 snd_una;
	__u32 snd_cwnd;
	__u32 ssthresh;
	__u32 snd_wnd;
	__u32 srtt;
	__u32 rcv_wnd;
	__u64 sock_cookie;
	*/
};

const struct event *unused __attribute__((unused));

SEC("tracepoint/tcp_probe")
// SEC("tracepoint/tcp_rcv_established")
int tcp_probe(struct tcp_entry* args) {
	struct event info = {};

	bpf_probe_read(&info.saddr, sizeof(info.saddr), &args->saddr);
	bpf_probe_read(&info.daddr, sizeof(info.daddr), &args->daddr);
	bpf_probe_read(&info.sport, sizeof(info.sport), &args->sport);
	bpf_probe_read(&info.dport, sizeof(info.dport), &args->dport);

	bpf_printk("saddr: %s\n", info.saddr);
	bpf_printk("daddr: %s\n", info.daddr);
	bpf_printk("sport: %d\n", info.sport);
	bpf_printk("dport: %d\n", info.dport);

	return 0;
}