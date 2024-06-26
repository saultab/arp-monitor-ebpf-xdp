# arp-monitoring-ebpf-xdp

Program for the arp monitoring with eBPF using XDP like hook point

## Building

Install pre-requirements on Ubuntu:
```sh
sudo apt update
sudo apt install -y clang libelf-dev zlib1g-dev gcc-multilib
```

Install pre-requirements on Fedora:
```sh
sudo dnf update
sudo dnf install clang llvm
sudo dnf install elfutils-libelf-devel perf glibc-devel.i686
```

Init libbpf and bpftool submodules:
```sh
git submodule update --init --recursive
```

Build and install libbpf:
```sh
cd ./libbpf/src
make
sudo make install
# Make sure the loader knows where to find libbpf
sudo ldconfig /usr/lib64
```

Build and install bpftool:
```sh
cd ./bpftool/src
make
sudo make install
```

Disable large-receive-offload:
```sh
sudo ethtool -K <ifname> lro off
```

Build and run the arp monitor:
```sh
make
sudo ./ringbuf-reserve-submit <ifname>
```
