# Tutorial 01

In this tutorial we will be writing an XDP program to block ssh.
There are two components in this tutorial, as follows:
- XDP program that will be loaded into the kernel. (`xdp_port_block.c`)
- Userspace program to load the XDP program into kernel. (`xdp_loader.c`)

To load the XDP program into the kernel using `xdp_loader`, the following command has to be used:

```bash
$ sudo ./xdp_loader --dev <interface>
```

NOTE: This `xdp_loader` just loads the XDP program into the kernel and does not unload it. In order to load susequent XDP program over the same interface you will have to unload it manually. Please refer to this [doc](../docs/ReadMe.md) to see how to unload XDP programs from an interface.