#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fdtable.h>

#define MAX_MSG_LEN 50
#define MAX_FILEPATH_SIZE 100
#define MAX_FILE_AND_DIR_NAME_SIZE 10
#define MAX_DIR_LEVELS_ALLOWED 6

struct data_t {
    u32 pid;                    /* kernel's view of the pid */
    u32 tgid;                   /* process's view of the pid */
    u64 ts;                     /* time in nanosecs since boot */
    char comm[TASK_COMM_LEN];   /* command for the task */
    unsigned int fd;            /* file descriptor */
    char msg[MAX_MSG_LEN];      /* application log message string (lms) */
};

/* Compare null-terminated strings (whose sizes are known) passed for equality */
static inline int string_cmp(
    const unsigned char *string1,
    const unsigned char *string2,
    unsigned int size1,
    unsigned int size2)
{
    if(size1 != size2) {
        return -1;
    }
    for(int i = 0; i < size1; ++i) {
        if(string1[i] != string2[i]) {
            return -1;
        }
    }
    return 0;
}

/* SUBJECT TO CHANGE */
/* Check if the filepath to which the write call is equal to - "/var/log/app/.*" */
static inline int check_log_filepath(unsigned int fd) {
    struct files_struct *files = NULL;
    struct fdtable *fdt = NULL;
    struct file **_fdt = NULL;
    struct file *f = NULL;
    struct dentry *de = NULL;
    struct dentry *de_parent = NULL;

    int nread = 0;
    int buf_cnt = 0;
    int i = 1;

    const unsigned char dirname_var[] = {'v','a','r','\\0'};
    const unsigned char dirname_log[] = {'l','o','g','\\0'};
    const unsigned char dirname_app[] = {'a','p','p','\\0'};

    int var_dirlevel = -1; /* Root directory is the lowest level */
    int log_dirlevel = -1;
    int app_dirlevel = -1;

    struct task_struct *curr = (struct task_struct *)bpf_get_current_task();
    bpf_probe_read_kernel(&files, sizeof(files), &curr->files);
    bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
    bpf_probe_read_kernel(&_fdt, sizeof(_fdt), &fdt->fd);
    bpf_probe_read_kernel(&f, sizeof(f), &_fdt[fd]);
    bpf_probe_read_kernel(&de, sizeof(de), &f->f_path.dentry);

    /* Iterate up the dentry hierarchy and store the lowest levels at which
    "var/", "log/" and "dir/" occur. If the filepath is "/var/log/app/.*" then
    these levels occur as consecutive integers and thus return 1, else return 0 */
    for (i = MAX_DIR_LEVELS_ALLOWED; i >= 1; --i) {
        bpf_probe_read_kernel(&de_parent, sizeof(de_parent), &de->d_parent);
        if(de_parent == NULL) {
            break;
        }

        struct qstr d_name = {};
        unsigned char name[MAX_FILEPATH_SIZE];
        unsigned int len;

        bpf_probe_read_kernel(&d_name, sizeof(d_name), &de_parent->d_name);
        bpf_probe_read_kernel(&len, sizeof(len), &d_name.len);
        bpf_probe_read_kernel_str(name, MAX_FILEPATH_SIZE, d_name.name);

        if(string_cmp(name, dirname_var, len+1, 4) == 0) {
            var_dirlevel = i;
        }
        if(string_cmp(name, dirname_log, len+1, 4) == 0) {
            log_dirlevel = i;
        }
        if(string_cmp(name, dirname_app, len+1, 4) == 0) {
            app_dirlevel = i;
        }

        de = de_parent;
    }

    return (app_dirlevel == log_dirlevel + 1 && log_dirlevel == var_dirlevel + 1);
}

BPF_PERF_OUTPUT(events);

int syscall__write(struct pt_regs *ctx,
    unsigned int fd,
    const char __user *buf,
	size_t count)
{
    struct data_t data = {};

    u64 tgid_pid = bpf_get_current_pid_tgid();
    data.pid = tgid_pid;
    data.tgid = (tgid_pid >> 32);

    /* If the write call was made by this bcc program it's useless */
    if(%ld == data.tgid) {
        return 0;
    }

    data.ts = bpf_ktime_get_boot_ns();
    data.fd = fd;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    /* Generate system log */

    /* If write call writes to a file in the log directory, generate application log */
    if(check_log_filepath(fd)) {
        int i = 0;
        int c = 5;
        int cnt = count;
        while(c--) {
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