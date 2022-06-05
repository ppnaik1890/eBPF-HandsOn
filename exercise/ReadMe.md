# Exercise

Problem statement:
Using an XDP program tell all the TCP ports on our system that other systems iteracted with over a particluar interface.
Basically, the task is to look at all the TCP packets and store all the destination port numbers from into a map.


The userspace program that will ooad the XDP program and print all the port numbers from the map is already provided.

You will have to just write the XDP program. (`xdp_snoop_port.c`)


To load the XDP program into the kernel using `xdp_load_and_print_port`, the following command has to be used:

```bash
$ sudo ./xdp_load_and_print_port --dev <interface>
```

# Debugging in XDP
While you are at writing the XDP program in exercise section, you might feel the need to print debug statements from your XDP program. Unlike userspace programs you cannot simply use any standard printing functions from the C Library. Instead the kernel provides you a function to print messages into tracefs buffer straight from your BPF program.

The `bpf_trace_printk()` helper function is very useful when debugging or when there’s need for immediate feedback from the eBPF program. Linux kernel provides BPF helper, `bpf_trace_printk()`, with the following definition:

```c
long bpf_trace_printk(const char *fmt, __u32 fmt_size, ...);
```

Here, is an example to show you how to use it in an actual XDP program:

```c
char fmt[] = "Packet received on port: %d\n";
bpf_trace_printk(fmt, sizeof(fmt), port);
```

It's first argument, `fmt`, is a pointer to a printf-compatible format string. `fmt_size` is the size of that string, including terminating \0. The varargs are arguments referenced from format string.

## Tracefs pipe reader
To retrieve the message printed by `bpf_trace_printk()`, you can read tracefs buffer directly using the following command:
```bash
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
```
