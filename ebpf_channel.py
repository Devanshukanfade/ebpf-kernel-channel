from bcc import BPF

# Part A: The Kernel Code (C Language)
ebpf_code = """
#include <uapi/linux/ptrace.h>

// Define the data structure
struct data_t {
    u32 pid;
    char command[16];
};

// Create the Perf Buffer channel
BPF_PERF_OUTPUT(events);

int trace_start(struct pt_regs *ctx) {
    struct data_t data = {};
    
    // Get the Process ID (Fixed: 'pid' instead of 'pit')
    data.pid = bpf_get_current_pid_tgid() >> 32;
    
    // Get the name of the command
    bpf_get_current_comm(&data.command, sizeof(data.command));
    
    // Send to User Space
    events.perf_submit(ctx, &data, sizeof(data));
    
    return 0;
}
"""

# Part B: The User Space Code (Python)
try:
    # Initialize BPF (Fixed: Correct function and syscall names)
    b = BPF(text=ebpf_code)
    b.attach_kprobe(event=b.get_syscall_fnname("execve"), fn_name="trace_start")
    
    print("DEBUG: Channel created. Waiting for Kernel events.... (Ctrl+C to Stop)")

    # Callback function to handle data from the Kernel
    def print_event(cpu, data, size):
        # Fixed: accessing the event structure correctly
        event = b["events"].event(data)
        print(f"[KERNEL CHANNEL] Process Detected: {event.command.decode()} | PID: {event.pid}")

    # Open the buffer and start polling
    b["events"].open_perf_buffer(print_event)
    while True:
        b.perf_buffer_poll()

except KeyboardInterrupt:
    print("\n[!] Stopping Kernel Monitor...")
    exit()
