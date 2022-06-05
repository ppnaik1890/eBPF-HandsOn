# VM with pre-installed packages
You can download a Qemu VM disk image and can host it on your machine for the sake of this tutorial. This VM is pre-insalled with all the dependencies and the repo is already present in the home directory. You can download the image using the following command, but only on **IIT Bombay Internal Network**:
```bash
$ curl http://charles_02.cse.iitb.ac.in/ubuntu22.04.qcow2 --output ubuntu22.04
```

# Manual installation of dependencies

Before you can start completing the steps in this XDP-tutorial, go though this document and install the needed software packages.

The main dependencies are `libbpf`, `llvm`, `clang` and `libelf`. LLVM+clang compiles our restricted-C programs into BPF-byte-code, which is stored in an ELF object file (`libelf`), that is loaded by `libbpf` into the kernel via the bpf syscall. Some of the lessons also use the perf utility to track the kernel behaviour through tracepoints.

The Makefiles in this repo will try to detect if you are missing some dependencies, and give you some pointers. 


## Packages on Ubuntu
On Debian and Ubuntu installations, install the dependencies like this:

```console
$ sudo apt install clang llvm libelf-dev libpcap-dev gcc-multilib build-essential libbpf-dev
```
## Kernel headers dependency
The Linux kernel provides a number of header files, which are usually installed in `/usr/include/linux`. The different Linux distributions usually provide a software package with these headers.

Some of the header files (we depend on) are located in the kernel tree under `include/uapi/linux/` (e.g. `include/uapi/linux/bpf.h`), but you should not include those files as they go through a conversion process when exported/installed into distros’ `/usr/include/linux` directory. In the kernel git tree you can run the command: make headers_install which will create a lot of headers files in directory “`usr/`”.

For now, this tutorial depends on kernel headers package provided by your distro.


For now, this tutorial depends on kernel headers package provided by your distro.

```console
$ sudo apt install linux-headers-$(uname -r)
```

## Recommended tools
The bpftool is the recommended tool for inspecting BPF programs running on your system. It also offers simple manipulation of eBPF programs and maps. In our tutorials, we will be loading our programs using bpftool. The bpftool is part of the Linux kernel tree under `tools/bpf/bpftool/`, but some Linux distributions also ship the tool as a software package. For installing `bpftool` on Ubuntu use the following command:
```console
$ sudo apt install linux-tools-common linux-tools-generic
```
