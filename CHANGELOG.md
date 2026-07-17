# Changelog

All notable changes to this project are documented in this file.

## [2.0.0]

### Breaking Changes
- **Renamed binary**: `ringbuf-reserve-submit` → `arp-monitor`
- **CLI interface**: Interface is now passed via `-i <name>` flag instead of positional argument
- **Requires system libbpf 1.x**: No longer bundles libbpf/bpftool as git submodules by default (vendored build still available via `make VENDORED_LIBBPF=1`)
- **Requires BTF-enabled kernel**: Uses `vmlinux.h` generated from `/sys/kernel/btf/vmlinux` for CO-RE portability instead of kernel headers

### Added

#### ARP Spoofing Detection
- **IP→MAC tracking table** (hash table, 1024 entries) in both kernel (`BPF_MAP_TYPE_HASH`) and userspace
- **Flip-count based alerting**: MAC change counter per IP, configurable threshold (`-t/--threshold`)
- **Whitelist support** (`-w/--whitelist ip,mac`): exclude known IP-MAC pairs from spoof detection
- **Spoof status in output**: each event tagged with `ok`, `new_host`, `mac_changed`, `SPOOF_ALERT`, or `whitelisted`

#### CLI (`getopt_long`)
- `-i, --interface` — network interface (required)
- `-v, --verbose` — debug-level logging
- `-j, --json` — JSON output (one object per line, machine-readable)
- `-t, --threshold` — MAC flip threshold for spoof alerts
- `-w, --whitelist` — IP,MAC whitelist entry (repeatable)
- `-d, --daemon` — background/daemon mode
- `-l, --log-file` — log to file
- `-s, --syslog` — log to syslog
- `-h, --help` — usage information

#### Structured Logging (`src/log.h`)
- Four log levels: `DEBUG`, `INFO`, `WARN`, `ERR`
- ISO 8601 timestamps with milliseconds
- File/line info in DEBUG mode
- Syslog backend support
- File output support

#### Signal Handling & Graceful Shutdown
- `sigaction()` for `SIGINT`/`SIGTERM` (replaces raw `signal()`)
- Clean detach of XDP program on exit
- Ring buffer and skeleton cleanup via `goto cleanup` pattern
- Output flush before exit
- Summary statistics on shutdown

#### Testing
- **Unit tests** (`tests/test_spoof_detect.c`): 9 tests covering spoof detection logic (new host, same MAC, MAC change, threshold alert, whitelist bypass, counter accuracy)
- **Integration tests** (`tests/integration_test.sh`): automated veth+namespace setup, ARP capture verification, spoof detection with MAC change simulation

#### CI/CD (`.github/workflows/ci.yml`)
- Multi-OS matrix (Ubuntu 22.04, 24.04)
- Clang-format check
- cppcheck static analysis
- BPF program compilation and verifier check
- Unit tests with and without AddressSanitizer
- ASan/UBSan build

#### Build System
- Strict compiler flags: `-Wall -Wextra -Werror -pedantic -std=gnu11`
- `make SANITIZE=1` for ASan/UBSan builds
- `make format` for auto-formatting
- `make check` for static analysis
- `make test-unit` / `make test-integration`
- `vmlinux.h` auto-generation from BTF

### Changed
- **Project structure**: flat layout → `src/`, `include/`, `tests/`, `docs/` (libbpf-bootstrap convention)
- **BPF program**: rewritten with proper CO-RE support (`vmlinux.h`), explicit ARP Ethernet/IPv4 validation (`ar_hln=6, ar_pln=4`)
- **Shared header**: `common.h` → `include/arp_monitor.h`, replaced BSD types (`u_int16_t`) with portable `__u16`/`__u8`
- **Ring buffer event struct**: added `ifindex` field, renamed to `struct arp_event`
- **Kernel-side ARP table**: new `BPF_MAP_TYPE_HASH` map for per-IP MAC tracking
- **Makefile**: complete rewrite with proper dependency tracking, vmlinux.h generation, system libbpf linking
- **Dockerfile**: upgraded to Ubuntu 24.04, multi-stage build with minimal runtime image, proper layer caching

### Removed
- `bump_memlock_rlimit()` — obsolete on kernel ≥5.11 (memcg-based accounting)
- `if_arp.h` local copy — replaced by `vmlinux.h` BTF definitions
- `common.h` — replaced by `include/arp_monitor.h`
- Empty `libbpf/` and `bpftool/` submodule directories (use system packages)

### Fixed
- Non-standard types in shared header (was failing with `clang -target bpf`)
- Missing bounds check after ARP header interpretation (verifier would reject on some kernels)
- No cleanup on `bpf_xdp_attach()` failure (XDP program left dangling)
- `signal()` replaced with `sigaction()` for portable, reliable signal handling
- Ring buffer `NULL` check now logs error instead of silently continuing

### Security
- Input validation on all CLI arguments (threshold range check, MAC format validation, interface existence check)
- Explicit packet bounds verification at every layer (Ethernet → ARP)
- ARP protocol validation (hardware/protocol length fields)
- No buffer overflows: all string operations use length-bounded variants
- ASan/UBSan clean in CI

---

## [1.0.0]

Initial implementation:
- XDP hook for ARP packet capture
- `BPF_MAP_TYPE_RINGBUF` communication
- Basic text output with timestamp
- Positional interface argument
- libbpf/bpftool as git submodules
