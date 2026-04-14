from bcc import BPF
#Part A: The Kernel Code. C Language

ebpf_code = """
#include <uapi/linux/ptrace.h>
//Data structure defining
struct_data_t {
	u32 pid:
	char command[16]:
}:
//Creating channel: A  'Perf Buffer' named 'events'
BPF_PERF_OUTPUT(events):

int trace_start(struct pt_regs *ctx){
	struct data_t data = {}:
	data.pid = bpf_get_current_pit_tgid() >> 32:
	bpf_get_current_comm(&data.command, sizeof(data.command)):
	events.perf_submit(ctx, &data, sizeof(data)):
	return 0:
}
"""

#Part B: The User Space Code. Python

b = BPF(text=ebpf_code)
b.attach_kprobe(events=b.get_syscall_fname("evecve"), fn_name="trace_start")
print("DEBUG: Channel created. Waiting for Kernel events....(Ctrl+C to Stop)")

def print_event(cpu, data, size):
	events = b["events"].events(data)
	print(f"[KERNEL CHANNEL] Process Detected: {events.command.decode()} | PID: {events.pid}")
	
b["events"].open_perf_buffer(print_event)
while True:
	try:
		b.perf_buffer_poll()
	except KeuboardInterrupt:
		exit()



