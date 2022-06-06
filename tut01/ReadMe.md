# Tutorial 01

In this tutorial we will be writing an XDP program to block ssh.
There are two components in this tutorial, as follows:
- XDP program that will be loaded into the kernel. (`xdp_port_block.c`)
- Userspace program to load the XDP program into kernel. (`xdp_loader.c`)

To load the XDP program into the kernel using `xdp_loader`, the following command has to be used:

```bash
$ sudo ./xdp_loader --dev <interface>
```

## Unloading of XDP BPF object files.
You can remove the existing XDP program from the interface, the following command must be issued:
```bash
$ ip link set dev <interface> xdp off
```
