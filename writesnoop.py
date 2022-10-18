import os
from bcc import BPF
from bcc.utils import printb
from bcc.containers import filter_by_containers

pid_self = os.getpid()

print(pid_self)

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_MSG_LEN 500

struct data_t {
    u32 pid;    // kernel's view of the pid
    u32 tgid;   // process's view of the pid
    u64 ts;     // timestamp
    char comm[TASK_COMM_LEN];   // command for the task
    char msg[20];
    unsigned int param1;
};

BPF_PERF_OUTPUT(events);

int syscall__write(struct pt_regs *ctx,
    unsigned int fd,
    const char __user *buf,
	size_t count)
{
    if(fd == 1 || fd == 2)
    {
        struct data_t data = {};

        u64 tgid_pid = bpf_get_current_pid_tgid();
        data.pid = tgid_pid;
        data.tgid = (tgid_pid >> 32);
        data.ts = bpf_ktime_get_ns();
        data.param1 = fd;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        bpf_probe_read_user(data.msg, 14, (void *)buf);
        
        if(%ld == data.tgid) // do not write to perf_buffer for self
        {
            return 0;
        }

        events.perf_submit(ctx, &data, sizeof(data));
    }
    
    return 0;
    // char msg[MAX_MSG_LEN];
    // bpf_probe_read_user(msg, sizeof(msg), (void *)PT_REGS_PARM2(ctx));

    // events.perf_submit(ctx, &data, sizeof(data));
}
""" % (pid_self)

# load BPF program
b = BPF(text=prog)

b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="syscall__write")

# header
print("%-18s %-16s %-6s %-6s %-6s" % ("TIME(s)", "COMM", "PID", "TGID", "PARAM1"))

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-16s %-6d %-6d %-6ld %s" % (time_s, str(event.comm), event.pid, event.tgid, event.param1, str(event.msg)))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()