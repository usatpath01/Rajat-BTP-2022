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