#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fdtable.h>

#define MAX_MSG_LEN 500
#define MAX_FILEPATH_SIZE 100
#define DEFAULT_SUB_BUF_LEN 10
#define DEFAULT_SUB_BUF_SIZE 10

struct data_t {
    u32 pid;    // kernel's view of the pid
    u32 tgid;   // process's view of the pid
    u64 ts;     // timestamp
    char comm[TASK_COMM_LEN];   // command for the task
    unsigned int fd;
    char filepath[MAX_FILEPATH_SIZE];
};

static int read_dentry_strings(
    struct dentry *dtryp,
    char buf[MAX_FILEPATH_SIZE])
{
    struct dentry dtry;
    struct dentry *lastdtryp = dtryp;
    int nread = 0;
    int buf_cnt = 0;
    if (buf) {
        bpf_probe_read_kernel(&dtry, sizeof(struct dentry), dtryp);
        bpf_probe_read_kernel_str(buf, strlen(dtry.d_name.name), dtry.d_name.name);
        nread++;
        buf_cnt += strlen(dtry.d_name.name);
        for (int i = 1; i < DEFAULT_SUB_BUF_LEN; i++) {
            if (dtry.d_parent != lastdtryp) {
                lastdtryp = dtry.d_parent;
                bpf_probe_read_kernel(&dtry, sizeof(struct dentry), dtry.d_parent);
                bpf_probe_read_kernel_str(buf + buf_cnt, strlen(dtry.d_name.name), dtry.d_name.name);
                nread++;
                buf_cnt += strlen(dtry.d_name.name);
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