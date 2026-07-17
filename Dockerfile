# Stage 1: Building
FROM ubuntu:24.04 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libelf-dev \
    zlib1g-dev \
    libbpf-dev \
    linux-tools-common \
    linux-tools-generic \
    make \
    gcc \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# The bpftool wrapper uses uname -r which won't match the Docker host kernel.
# Locate the real binary and symlink it to bypass the wrapper.
RUN REAL_BPFTOOL=$(find /usr/lib/linux-tools-* -name bpftool -type f 2>/dev/null | head -1) \
    && echo "Found bpftool at: $REAL_BPFTOOL" \
    && ln -sf "$REAL_BPFTOOL" /usr/local/bin/bpftool

WORKDIR /build
COPY . .

# Generate vmlinux.h from host BTF if available, otherwise use minimal fallback
RUN mkdir -p .output && \
    if bpftool btf dump file /sys/kernel/btf/vmlinux format c > .output/vmlinux.h 2>/dev/null; then \
        echo "vmlinux.h generated from BTF"; \
    else \
        cp include/vmlinux_minimal.h .output/vmlinux.h && \
        echo "Using minimal vmlinux.h fallback (no BTF available)"; \
    fi

RUN make

# Stage 2: Runtime
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libelf1 \
    libbpf1 \
    && rm -rf /var/lib/apt/lists/*

# Run as non-root where possible; eBPF attach requires
# CAP_BPF + CAP_NET_ADMIN granted at container runtime.
RUN useradd -r -s /usr/sbin/nologin arp-monitor
USER arp-monitor

COPY --from=builder /build/arp-monitor /usr/local/bin/arp-monitor

ENTRYPOINT ["arp-monitor"]
CMD ["-i", "eth0"]
