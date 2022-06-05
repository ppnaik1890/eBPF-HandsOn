# About XDP Modes
XDP supports three operation modes which `iproute2` implements as well: `xdpdrv`, `xdpoffload` and `xdpgeneric`.

- `xdpdrv` stands for native XDP, meaning the BPF program is run directly in the driver’s receive path at the earliest possible point in software. This is the normal/conventional XDP mode and requires driver’s to implement XDP support, which all major 10G/40G/+ networking drivers in the upstream Linux kernel already provide.

- `xdpgeneric` stands for generic XDP and is intended as an experimental test bed for drivers which do not yet support native XDP. Given the generic XDP hook in the ingress path comes at a much later point in time when the packet already enters the stack’s main receive path as a skb, the performance is significantly less than with processing in xdpdrv mode. `xdpgeneric` therefore is for the most part only interesting for experimenting, less for production environments.

- `xdpoffload` mode is implemented by SmartNICs such as those supported by Netronome’s nfp driver and allow for offloading the entire BPF/XDP program into hardware. This provides even higher performance than running in native XDP although not all BPF map types or BPF helper functions are available for use compared to native XDP. The BPF verifier will reject the program in such case and report to the user what is unsupported.


# Load XDP program using iproute2
This document shows you how to attach the bpf program to a network device(network interface) using `ip` utility. 

We will be using the `ip` utility to load and unload XDP programs, which is a part of the `iproute2` package.
Iproute2 is a collection of utilities for controlling TCP / IP networking and traffic control in Linux.
`ip` utility in Linux is used to show/manipulate the network devices and interfaces in Linux.

## Loading of XDP BPF object files.
Given a BPF object file prog.o has been compiled for XDP, it can be loaded through ip to a XDP-supported netdevice with the following command:
```bash
$ ip link set dev <interface> xdp obj <object-file> sec <section-name>
```
By default, ip will throw an error in case a XDP program is already attached to the networking interface, to prevent it from being overridden by accident. In order to replace the currently running XDP program with a new one, the `-force` option must be used:

```bash
$ ip -force link set dev <interface> xdp obj <object-file> sec <section-name>
```
When a command like `ip link set dev em1 xdp obj [...]` is used, then the kernel will attempt to load the program first as native XDP, and in case the driver does not support native XDP, it will automatically fall back to generic XDP. Thus, for example, using explicitly `xdpdrv` instead of `xdp`, the kernel will only attempt to load the program as native XDP and fail in case the driver does not support it, which provides a guarantee that generic XDP is avoided altogether.

## Unloading of XDP BPF object files.
You can remove the existing XDP program from the interface, the following command must be issued:
```bash
$ ip link set dev <interface> xdp off
```




## Reference
[Cilium Docs](https://docs.cilium.io/en/v1.9/bpf/)