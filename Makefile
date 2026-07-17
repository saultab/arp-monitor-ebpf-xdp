# SPDX-License-Identifier: MIT
# Makefile for arp-monitor — eBPF/XDP ARP traffic monitor
#
# Follows libbpf-bootstrap conventions.
# Requires: clang, llvm-strip, bpftool, libelf-dev, zlib1g-dev

OUTPUT       := .output
CLANG        ?= clang
LLVM_STRIP   ?= llvm-strip
BPFTOOL      ?= bpftool
CC           ?= gcc
LIBBPF_SRC   := $(abspath ./libbpf/src)
LIBBPF_OBJ   := $(abspath $(OUTPUT)/libbpf.a)

INCLUDES     := -I$(OUTPUT) -I./include -I./src
ARCH         := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')

# Strict compiler flags
CFLAGS       := -g -O2 -Wall -Wextra -Werror -pedantic -Wno-overlength-strings -std=gnu11
LDFLAGS      := -lelf -lz

# Sanitizer support (make SANITIZE=1)
ifdef SANITIZE
CFLAGS       += -fsanitize=address,undefined -fno-omit-frame-pointer
LDFLAGS      += -fsanitize=address,undefined
endif

APP          := arp-monitor
BPF_SRC      := src/arp_monitor.bpf.c
USER_SRC     := src/arp_monitor.c

ifeq ($(V),1)
	Q =
	msg =
else
	Q = @
	msg = @printf '  %-8s %s%s\n' \
		"$(1)" \
		"$(patsubst $(abspath $(OUTPUT))/%,%,$(2))" \
		"$(if $(3), $(3))";
	MAKEFLAGS += --no-print-directory
endif

.PHONY: all clean format check

all: $(APP)

clean:
	$(call msg,CLEAN)
	$(Q)rm -rf $(OUTPUT) $(APP)

# Create output directories
$(OUTPUT) $(OUTPUT)/libbpf:
	$(call msg,MKDIR,$@)
	$(Q)mkdir -p $@

# Generate vmlinux.h from BTF
$(OUTPUT)/vmlinux.h: | $(OUTPUT)
	$(call msg,GEN,$@)
	$(Q)$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

# Build BPF object
$(OUTPUT)/arp_monitor.bpf.o: $(BPF_SRC) $(OUTPUT)/vmlinux.h include/arp_monitor.h | $(OUTPUT)
	$(call msg,BPF,$@)
	$(Q)$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -D__BPF_PROGRAM__ \
		-I$(OUTPUT) -I./include -I./src \
		-c $< -o $@
	$(Q)$(LLVM_STRIP) -g $@

# Generate BPF skeleton
$(OUTPUT)/arp_monitor.skel.h: $(OUTPUT)/arp_monitor.bpf.o | $(OUTPUT)
	$(call msg,GEN-SKEL,$@)
	$(Q)$(BPFTOOL) gen skeleton $< > $@

# Build userspace object
$(OUTPUT)/arp_monitor.o: $(USER_SRC) $(OUTPUT)/arp_monitor.skel.h \
                         include/arp_monitor.h src/log.h src/spoof_detect.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) -I$(OUTPUT) -c $< -o $@

# Link final binary (system libbpf)
$(APP): $(OUTPUT)/arp_monitor.o
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ -lbpf $(LDFLAGS) -o $@

# Build with vendored libbpf (make VENDORED_LIBBPF=1)
ifdef VENDORED_LIBBPF
$(LIBBPF_OBJ): $(wildcard $(LIBBPF_SRC)/*.[ch] $(LIBBPF_SRC)/Makefile) | $(OUTPUT)/libbpf
	$(call msg,LIB,$@)
	$(Q)$(MAKE) -C $(LIBBPF_SRC) BUILD_STATIC_ONLY=1 \
		OBJDIR=$(dir $@)/libbpf DESTDIR=$(dir $@) \
		INCLUDEDIR= LIBDIR= UAPIDIR= \
		install

$(APP): $(OUTPUT)/arp_monitor.o $(LIBBPF_OBJ)
	$(call msg,BINARY,$@)
	$(Q)$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@
endif

# Convenience targets
format:
	$(Q)find src/ include/ tests/ -name '*.[ch]' -exec clang-format -i {} +

check:
	$(Q)cppcheck --enable=all --suppress=missingIncludeSystem \
		-I./include -I./src src/*.c

# Tests
.PHONY: test test-unit test-integration

test: test-unit

test-unit: $(OUTPUT)/test_spoof_detect
	$(call msg,TEST,$<)
	$(Q)$(OUTPUT)/test_spoof_detect

$(OUTPUT)/test_spoof_detect: tests/test_spoof_detect.c src/spoof_detect.h include/arp_monitor.h | $(OUTPUT)
	$(call msg,CC,$@)
	$(Q)$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

test-integration:
	$(call msg,TEST,integration)
	$(Q)sudo tests/integration_test.sh

.DELETE_ON_ERROR:
.SECONDARY:
