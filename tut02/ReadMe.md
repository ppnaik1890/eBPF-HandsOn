# Tutorial 02

In this tutorial we will be building upon our previous XDP program to do two things.
- Count the total number of packets that arrived over that network interface.
- Count the number of packets that are blocked on ssh port.

There are two components in this tutorial, as follows:
- XDP program that will be loaded into the kernel. (`xdp_count_dropped.c`)
- Userspace program to load the XDP program into kernel. This program will also display the respective counts which will refresh with an interval of 2 seconds. (`xdp_load_and_print_stats.c`)

In order to sstore the count of the packets arrived and dropped, we will be using BPF Maps.

To load the XDP program into the kernel using `xdp_load_and_print_stats`, the following command has to be used:

```bash
$ sudo ./xdp_load_and_print_stats --dev <interface>
```