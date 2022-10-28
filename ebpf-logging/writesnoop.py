import os
from bcc import BPF
from bcc.utils import printb
from bcc.containers import filter_by_containers

pid_self = os.getpid()

print(pid_self)

prog = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fdtable.h>

#define MAX_MSG_LEN 500
#define DEFAULT_SUB_BUF_LEN 10
#define DEFAULT_SUB_BUF_SIZE 10

struct data_t {
    u32 pid;    // kernel's view of the pid
    u32 tgid;   // process's view of the pid
    u64 ts;     // timestamp
    char comm[TASK_COMM_LEN];   // command for the task
    unsigned int fd;
    char filepath[DEFAULT_SUB_BUF_LEN][DEFAULT_SUB_BUF_SIZE];
};

static int read_dentry_strings(
    struct dentry *dtryp,
    char buf[DEFAULT_SUB_BUF_LEN][DEFAULT_SUB_BUF_SIZE])
{
    struct dentry dtry;
    struct dentry *lastdtryp = dtryp;
    int nread = 0;
    int i = 0;
    if (buf) {
        bpf_probe_read(&dtry, sizeof(struct dentry), dtryp);
        bpf_probe_read_str(buf[i], DEFAULT_SUB_BUF_SIZE, dtry.d_name.name);
        nread++;
        for (i = 1; i < DEFAULT_SUB_BUF_LEN; i++) {
            if (dtry.d_parent != lastdtryp) {
                lastdtryp = dtry.d_parent;
                bpf_probe_read(&dtry, sizeof(struct dentry), dtry.d_parent);
                bpf_probe_read_str(buf[i], DEFAULT_SUB_BUF_SIZE, dtry.d_name.name);
                nread++;
            } else
                break;
        }
    }
    return nread;
}

BPF_PERF_OUTPUT(events);
BPF_HASH

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
        data.fd = fd;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));
        // bpf_probe_read_user(data.msg, 50, (void *)buf);

        struct files_struct *files = NULL;
        struct fdtable *fdt = NULL;
        struct file *f = NULL;
        struct dentry *de = NULL;
        struct qstr dn = {};

        struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
        bpf_probe_read_kernel(&files, sizeof(files), &curr->files);
        bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
        struct file **_fd = NULL;
        bpf_probe_read(&_fd, sizeof(_fd), &fdt->fd);
        bpf_probe_read(&f, sizeof(f), &_fd[fd]);
        bpf_probe_read_kernel(&de, sizeof(de), &f->f_path.dentry);
        bpf_probe_read_kernel(&dn, sizeof(dn), &de->d_name);

        read_dentry_strings(de, data.filepath);
        
        if(%ld == data.tgid) // do not write to perf_buffer for self
        {
            return 0;
        }

        events.perf_submit(ctx, &data, sizeof(data));
    }
    
    return 0;
}
""" % (pid_self)

# load BPF program
b = BPF(text=prog)

b.attach_kprobe(event=b.get_syscall_fnname("write"), fn_name="syscall__write")

# header
print("%-18s %-16s %-6s %-6s %-6s" % ("TIME(s)", "COMM", "PID", "TGID", "FD"))

# process event
start = 0
def print_event(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
            start = event.ts
    time_s = (float(event.ts - start)) / 1000000000
    print("%-18.9f %-16s %-6d %-6d %-6ld %s" % (time_s, str(event.comm), event.pid, event.tgid, event.fd, (event.filepath)[0]))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()