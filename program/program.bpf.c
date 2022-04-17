#include "vmlinux.h"
#include "bpf_helpers.h"

char __license[] SEC("license") = "GPL";

struct enter_accept4 {
	u32					_unused1;
	u32					_unused2;
	u64					fd;
	struct sockaddr*	user_sockaddr;
	int*				user_addrlen;
	int					flags;
};

struct exit_accept4 {
	u32	_unused1;
	u32	_unused2;

	u32	ret;
};

struct enter_close {
	u32	_unused1;
	u32	_unused2;

	u64	fd;
};

struct all_info {
	pid_t	pid;
	u64		fd;
	u64		start_time;
	u64		end_time;
};

struct event {
	pid_t	pid;
	u32		ret;
	u64		fd;
	u64		start_time;
	u64		end_time;
	u64		duration_ms;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, struct all_info);
	__uint(max_entries, 10);
} time_events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, int);
	__type(value, struct event);
	__uint(max_entries, 10);
} events SEC(".maps");

const struct event *unused __attribute__((unused));

SEC("tracepoint/sys_enter_accept4")
int sys_enter_accept4(struct enter_accept4* args)
{
	struct all_info	data = {};
	pid_t			pid = bpf_get_current_pid_tgid() >> 32;

	data.pid = pid;
	bpf_probe_read(&data.fd, sizeof(data.fd), args->fd);
	data.start_time = bpf_ktime_get_ns();

	bpf_map_update_elem(&time_events, &pid, &data, BPF_ANY);

	bpf_printk("111 SysEnterAccept4 111");
	bpf_printk("pid: %d", data.pid);
	bpf_printk("fd: %d", data.fd);
	bpf_printk("start: %ld\n", data.start_time);
	return 0;
}

SEC("tracepoint/sys_exit_accept4")
int sys_exit_accept4(struct exit_accept4* args)
{
	pid_t				pid = bpf_get_current_pid_tgid() >> 32;
	struct all_info*	tmp = bpf_map_lookup_elem(&time_events, &pid);

	tmp->start_time = bpf_ktime_get_ns();
	bpf_map_update_elem(&time_events, &pid, tmp, BPF_ANY);

	bpf_printk("222 SysExitAccept4 222");
	bpf_printk("pid: %d", tmp->pid);
	bpf_printk("fd: %d", tmp->fd);
	bpf_printk("start: %ld\n", tmp->start_time);
	return 0;
}

SEC("tracepoint/sys_enter_close")
int sys_enter_close(struct enter_close* args)
{
	pid_t				pid = bpf_get_current_pid_tgid() >> 32;
	struct all_info*	tmp = bpf_map_lookup_elem(&time_events, &pid);
	struct event		data = {};

	data.pid = pid;
	if (tmp->fd == args->fd) {
		bpf_printk("Both have same fd: %d\n", tmp->fd);
		bpf_probe_read(&data.fd, sizeof(data.fd), args->fd);
	} else {
		bpf_printk("Different fd: %d vs %d\n", tmp->fd, args->fd);
		return 0;
	}
	data.end_time = bpf_ktime_get_ns();
	data.duration_ms = data.end_time - data.start_time;
	bpf_map_update_elem(&events, &data.fd, &data, BPF_ANY);

	// 문제는... main.go에서는 fd값을 모르는데 어떻게 events map에서 데이터를 가져오냐 이거야.
	// 일단 지금 생각해본 방법은 enter_execve4에서 fd를 구하니까 이것만 저장하는 map을 또 만들고
	// main.go에서는 여기서 fd값을 얻어서 이 값으로 events map에 접근한다.
	bpf_map_delete_elem(&events, &pid);


	bpf_printk("333 SysEnterClose 333");
	bpf_printk("pid: %d", data.pid);
	bpf_printk("fd: %d", data.fd);
	bpf_printk("start: %ld", data.start_time);
	bpf_printk("start: %ld\n", data.end_time);
	return 0;
}