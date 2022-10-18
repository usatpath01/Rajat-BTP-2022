from bcc import BPF
prog="""
int kprobe__sys_sync(void* ctx)
{
    bpf_trace_printk("sys_sync() called.");
    return 0;
}
"""
print("Tracing sys_sync()... Ctrl-C to end.")
try:
    BPF(text = prog).trace_print()
except KeyboardInterrupt:
    exit(1)