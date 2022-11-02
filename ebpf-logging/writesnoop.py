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

#define MAX_MSG_LEN 50
#define MAX_FILEPATH_SIZE 100
#define MAX_FILE_AND_DIR_NAME_SIZE 10
#define MAX_DIR_LEVELS 10
#define DEFAULT_SUB_BUF_LEN 10
#define DEFAULT_SUB_BUF_SIZE 10

struct data_t {
    u32 pid;    // kernel's view of the pid
    u32 tgid;   // process's view of the pid
    u64 ts;     // timestamp
    char comm[TASK_COMM_LEN];   // command for the task
    unsigned int fd;
    char filepath[MAX_FILEPATH_SIZE];
    char msg[MAX_MSG_LEN];
    int msg_length_read;
};

static inline int read_dentry_strings(
    const struct dentry *dentry_ptr,
    char buf[MAX_FILEPATH_SIZE])
{
    struct dentry dtry;
    const struct dentry *dtry_ptr = dentry_ptr;
    const struct dentry *dtry_parent_ptr;
    int nread = 0;
    int buf_cnt = 0;
    int i = 0;
    if (buf) {
        for (i = 0; i < DEFAULT_SUB_BUF_LEN; i++) {
            bpf_probe_read_kernel((void *)&dtry_parent_ptr, sizeof(struct dentry *), (const void *)&dtry_ptr->d_parent);
            if (dtry_parent_ptr != dtry_ptr) {
                bpf_probe_read_kernel((void *)&dtry, sizeof(struct dentry), (const void *)dtry_ptr);
                bpf_probe_read_str((void *)buf + buf_cnt, MAX_FILEPATH_SIZE - buf_cnt, (const void *)dtry.d_name.name);
                nread++;
                buf_cnt += 3;
                dtry_ptr = dtry_parent_ptr;
            } else
                break;
        }
    }
    return nread;
}

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
        data.fd = fd;
        bpf_get_current_comm(&data.comm, sizeof(data.comm));

        struct files_struct *files = NULL;
        struct fdtable *fdt = NULL;
        struct file *f = NULL;
        struct dentry *de = NULL;

        struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
        bpf_probe_read_kernel(&files, sizeof(files), &curr->files);
        bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
        struct file **_fd = NULL;
        bpf_probe_read(&_fd, sizeof(_fd), &fdt->fd);
        bpf_probe_read(&f, sizeof(f), &_fd[fd]);
        bpf_probe_read_kernel(&de, sizeof(de), &f->f_path.dentry);

        read_dentry_strings(de, data.filepath);
        
        if(%ld == data.tgid) // do not write to perf_buffer for self
        {
            return 0;
        }

        int i = 0;
        int c = 5;
        int cnt = count;
        while(c--)
        {
            bpf_probe_read_user_str(data.msg, MAX_MSG_LEN, (void *)buf);
            events.perf_submit(ctx, &data, sizeof(data));
            cnt -= MAX_MSG_LEN;
            if(cnt < 0){
                break;
            }
            buf = buf + MAX_MSG_LEN - 1;
        }
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
    print("%-18.9f %-16s %-6d %-6d %-6ld %s %s" % (time_s, str(event.comm), event.pid, event.tgid, event.fd, event.filepath, event.msg))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()