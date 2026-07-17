// SPDX-License-Identifier: MIT
/*
 * arp_monitor.c — Userspace component of the ARP monitor
 *
 * Loads the eBPF/XDP program, attaches it to the specified interface,
 * polls the ring buffer for ARP events, and performs spoofing detection.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "arp_monitor.skel.h"
#include "../include/arp_monitor.h"
#include "log.h"
#include "spoof_detect.h"

/* ── Configuration ──────────────────────────────────────────────── */

struct config {
    char ifname[IFNAMSIZ];
    unsigned int ifindex;
    int verbose;
    int json_output;
    int daemon_mode;
    uint32_t flip_threshold;
    char log_file[256];
    int use_syslog;
};

static struct config cfg = {
    .ifname = "",
    .ifindex = 0,
    .verbose = 0,
    .json_output = 0,
    .daemon_mode = 0,
    .flip_threshold = DEFAULT_FLIP_THRESHOLD,
    .log_file = "",
    .use_syslog = 0,
};

/* ── Globals ────────────────────────────────────────────────────── */

static volatile sig_atomic_t exiting = 0;
static struct spoof_detector detector;

/* ── Signal handling ────────────────────────────────────────────── */

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static int setup_signals(void)
{
    struct sigaction sa = {
        .sa_handler = sig_handler,
        .sa_flags = SA_RESETHAND,
    };
    sigemptyset(&sa.sa_mask);

    if (sigaction(SIGINT, &sa, NULL) < 0) {
        LOG_ERR("Failed to set SIGINT handler: %s", strerror(errno));
        return -1;
    }
    if (sigaction(SIGTERM, &sa, NULL) < 0) {
        LOG_ERR("Failed to set SIGTERM handler: %s", strerror(errno));
        return -1;
    }
    return 0;
}

/* ── libbpf logging callback ────────────────────────────────────── */

static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !cfg.verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

/* ── Output formatting ──────────────────────────────────────────── */

static const char *opcode_str(uint16_t op)
{
    switch (op) {
    case 1: return "REQUEST";
    case 2: return "REPLY";
    case 3: return "RARP_REQUEST";
    case 4: return "RARP_REPLY";
    default: return "UNKNOWN";
    }
}

static const char *spoof_result_str(enum spoof_result r)
{
    switch (r) {
    case SPOOF_OK:          return "ok";
    case SPOOF_NEW_HOST:    return "new_host";
    case SPOOF_MAC_CHANGED: return "mac_changed";
    case SPOOF_ALERT:       return "SPOOF_ALERT";
    case SPOOF_WHITELISTED: return "whitelisted";
    default:                return "unknown";
    }
}

static void print_event_text(const struct arp_event *e,
                             enum spoof_result result)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    localtime_r(&ts.tv_sec, &tm);
    char timebuf[32];
    strftime(timebuf, sizeof(timebuf), "%H:%M:%S", &tm);

    printf("%-8s %-8s %02x:%02x:%02x:%02x:%02x:%02x  "
           "%d.%d.%d.%d  ->  "
           "%02x:%02x:%02x:%02x:%02x:%02x  "
           "%d.%d.%d.%d",
           timebuf, opcode_str(e->ar_op),
           e->ar_sha[0], e->ar_sha[1], e->ar_sha[2],
           e->ar_sha[3], e->ar_sha[4], e->ar_sha[5],
           e->ar_sip[0], e->ar_sip[1], e->ar_sip[2], e->ar_sip[3],
           e->ar_tha[0], e->ar_tha[1], e->ar_tha[2],
           e->ar_tha[3], e->ar_tha[4], e->ar_tha[5],
           e->ar_tip[0], e->ar_tip[1], e->ar_tip[2], e->ar_tip[3]);

    if (result == SPOOF_ALERT)
        printf("  ** SPOOF ALERT **");
    else if (result == SPOOF_MAC_CHANGED)
        printf("  [mac changed]");
    else if (result == SPOOF_NEW_HOST)
        printf("  [new host]");

    printf("\n");
    fflush(stdout);
}

static void print_event_json(const struct arp_event *e,
                             enum spoof_result result)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    printf("{\"timestamp\":%ld.%03ld,"
           "\"type\":\"%s\","
           "\"sender_mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
           "\"sender_ip\":\"%d.%d.%d.%d\","
           "\"target_mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
           "\"target_ip\":\"%d.%d.%d.%d\","
           "\"spoof_status\":\"%s\"}\n",
           ts.tv_sec, ts.tv_nsec / 1000000,
           opcode_str(e->ar_op),
           e->ar_sha[0], e->ar_sha[1], e->ar_sha[2],
           e->ar_sha[3], e->ar_sha[4], e->ar_sha[5],
           e->ar_sip[0], e->ar_sip[1], e->ar_sip[2], e->ar_sip[3],
           e->ar_tha[0], e->ar_tha[1], e->ar_tha[2],
           e->ar_tha[3], e->ar_tha[4], e->ar_tha[5],
           e->ar_tip[0], e->ar_tip[1], e->ar_tip[2], e->ar_tip[3],
           spoof_result_str(result));
    fflush(stdout);
}

/* ── Ring buffer event handler ──────────────────────────────────── */

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    (void)ctx;

    if (data_sz < sizeof(struct arp_event)) {
        LOG_WARN("Received truncated event (%zu bytes)", data_sz);
        return 0;
    }

    const struct arp_event *e = data;

    /* Build IP as u32 for spoof detection */
    uint32_t sender_ip;
    memcpy(&sender_ip, e->ar_sip, 4);

    enum spoof_result result = spoof_check(&detector, sender_ip, e->ar_sha);

    if (detector.table_resets > 0) {
        LOG_WARN("Spoof detection table was reset due to exhaustion "
                 "(possible ARP flood attack, %lu resets total)",
                 (unsigned long)detector.table_resets);
    }

    if (result == SPOOF_ALERT) {
        LOG_WARN("ARP spoofing detected: IP %d.%d.%d.%d MAC changed "
                 "(flip_count >= %u)",
                 e->ar_sip[0], e->ar_sip[1], e->ar_sip[2], e->ar_sip[3],
                 cfg.flip_threshold);
    }

    if (cfg.json_output)
        print_event_json(e, result);
    else
        print_event_text(e, result);

    return 0;
}

/* ── CLI ────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [OPTIONS] -i <interface>\n"
        "\n"
        "ARP Monitor — Real-time ARP traffic monitoring with spoofing detection\n"
        "\n"
        "Options:\n"
        "  -i, --interface <name>   Network interface to monitor (required)\n"
        "  -v, --verbose            Enable verbose/debug output\n"
        "  -j, --json               Output events as JSON (one per line)\n"
        "  -t, --threshold <N>      MAC flip threshold for spoof alert (default: %d)\n"
        "  -w, --whitelist <ip,mac> Add IP-MAC pair to whitelist (repeatable)\n"
        "  -d, --daemon             Run as daemon (background)\n"
        "  -l, --log-file <path>    Write logs to file instead of stderr\n"
        "  -s, --syslog             Send logs to syslog\n"
        "  -h, --help               Show this help message\n"
        "\n"
        "Examples:\n"
        "  %s -i eth0\n"
        "  %s -i eth0 -j -t 5\n"
        "  %s -i eth0 -w 192.168.1.1,aa:bb:cc:dd:ee:ff -d\n",
        prog, DEFAULT_FLIP_THRESHOLD, prog, prog, prog);
}

static int parse_whitelist(const char *arg, uint32_t *ip, uint8_t mac[6])
{
    unsigned int a, b, c, d;
    unsigned int m[6];

    int ret = sscanf(arg, "%u.%u.%u.%u,%02x:%02x:%02x:%02x:%02x:%02x",
                     &a, &b, &c, &d,
                     &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]);
    if (ret != 10)
        return -1;

    if (a > 255 || b > 255 || c > 255 || d > 255)
        return -1;
    for (int i = 0; i < 6; i++) {
        if (m[i] > 255)
            return -1;
    }

    uint8_t ip_bytes[4] = {(uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d};
    memcpy(ip, ip_bytes, 4);
    for (int i = 0; i < 6; i++)
        mac[i] = (uint8_t)m[i];

    return 0;
}

static int parse_args(int argc, char **argv)
{
    static const struct option long_opts[] = {
        {"interface", required_argument, NULL, 'i'},
        {"verbose",   no_argument,       NULL, 'v'},
        {"json",      no_argument,       NULL, 'j'},
        {"threshold", required_argument, NULL, 't'},
        {"whitelist", required_argument, NULL, 'w'},
        {"daemon",    no_argument,       NULL, 'd'},
        {"log-file",  required_argument, NULL, 'l'},
        {"syslog",    no_argument,       NULL, 's'},
        {"help",      no_argument,       NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "i:vjt:w:dl:sh", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'i':
            strncpy(cfg.ifname, optarg, IFNAMSIZ - 1);
            cfg.ifname[IFNAMSIZ - 1] = '\0';
            break;
        case 'v':
            cfg.verbose = 1;
            break;
        case 'j':
            cfg.json_output = 1;
            break;
        case 't': {
            char *endptr;
            long val = strtol(optarg, &endptr, 10);
            if (*endptr != '\0' || val <= 0 || val > 1000) {
                fprintf(stderr, "Invalid threshold: %s (must be 1-1000)\n", optarg);
                return -1;
            }
            cfg.flip_threshold = (uint32_t)val;
            break;
        }
        case 'w': {
            uint32_t ip;
            uint8_t mac[6];
            if (parse_whitelist(optarg, &ip, mac) < 0) {
                fprintf(stderr, "Invalid whitelist format: %s\n"
                        "Expected: IP,MAC (e.g., 192.168.1.1,aa:bb:cc:dd:ee:ff)\n",
                        optarg);
                return -1;
            }
            if (spoof_add_whitelist(&detector, ip, mac) < 0) {
                fprintf(stderr, "Whitelist full (max 64 entries)\n");
                return -1;
            }
            break;
        }
        case 'd':
            cfg.daemon_mode = 1;
            break;
        case 'l':
            strncpy(cfg.log_file, optarg, sizeof(cfg.log_file) - 1);
            cfg.log_file[sizeof(cfg.log_file) - 1] = '\0';
            break;
        case 's':
            cfg.use_syslog = 1;
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            usage(argv[0]);
            return -1;
        }
    }

    if (cfg.ifname[0] == '\0') {
        fprintf(stderr, "Error: interface name is required (-i <name>)\n");
        usage(argv[0]);
        return -1;
    }

    cfg.ifindex = if_nametoindex(cfg.ifname);
    if (cfg.ifindex == 0) {
        fprintf(stderr, "Error: interface '%s' not found: %s\n",
                cfg.ifname, strerror(errno));
        return -1;
    }

    return 0;
}

/* ── Daemonize ──────────────────────────────────────────────────── */

#define PID_FILE "/var/run/arp-monitor.pid"

static int daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        LOG_ERR("fork() failed: %s", strerror(errno));
        return -1;
    }
    if (pid > 0)
        _exit(0);  /* Parent exits */

    if (setsid() < 0) {
        LOG_ERR("setsid() failed: %s", strerror(errno));
        return -1;
    }

    /* Write PID file */
    FILE *pf = fopen(PID_FILE, "w");
    if (pf) {
        fprintf(pf, "%d\n", getpid());
        fclose(pf);
    } else {
        LOG_WARN("Could not create PID file %s: %s", PID_FILE, strerror(errno));
    }

    /* Redirect stdin/stdout/stderr to /dev/null */
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        if (!cfg.json_output)
            dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > STDERR_FILENO)
            close(fd);
    }

    return 0;
}

/* ── Main ───────────────────────────────────────────────────────── */

int main(int argc, char **argv)
{
    struct arp_monitor_bpf *skel = NULL;
    struct ring_buffer *rb = NULL;
    int err = 0;

    /* Initialize spoof detector (needs to happen before parse_args for whitelist) */
    spoof_detector_init(&detector, cfg.flip_threshold);

    /* Parse command line */
    if (parse_args(argc, argv) < 0)
        return 1;

    /* Update threshold after parsing (in case -t came after -w) */
    detector.flip_threshold = cfg.flip_threshold;

    /* Initialize logging */
    FILE *log_fp = NULL;
    if (cfg.log_file[0] != '\0') {
        log_fp = fopen(cfg.log_file, "a");
        if (!log_fp) {
            fprintf(stderr, "Failed to open log file '%s': %s\n",
                    cfg.log_file, strerror(errno));
            return 1;
        }
    }
    log_init(cfg.verbose ? LOG_LVL_DEBUG : LOG_LVL_INFO,
             log_fp, cfg.use_syslog);

    LOG_INFO("ARP Monitor starting on interface %s (ifindex %u)",
             cfg.ifname, cfg.ifindex);
    LOG_INFO("Spoof detection threshold: %u flips", cfg.flip_threshold);

    /* Set up libbpf */
    libbpf_set_print(libbpf_print_fn);

    /* Set up signal handlers */
    if (setup_signals() < 0) {
        err = 1;
        goto cleanup;
    }

    /* Load and verify BPF program */
    skel = arp_monitor_bpf__open_and_load();
    if (!skel) {
        LOG_ERR("Failed to open and load BPF skeleton: %s", strerror(errno));
        err = 1;
        goto cleanup;
    }
    LOG_DEBUG("BPF program loaded successfully");

    /* Attach XDP program */
    err = bpf_xdp_attach(cfg.ifindex,
                          bpf_program__fd(skel->progs.arp_monitor_xdp),
                          0, NULL);
    if (err) {
        LOG_ERR("Failed to attach XDP program to %s: %s",
                cfg.ifname, strerror(errno));
        goto cleanup;
    }
    LOG_INFO("XDP program attached to %s", cfg.ifname);

    /* Set up ring buffer */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb),
                          handle_event, NULL, NULL);
    if (!rb) {
        LOG_ERR("Failed to create ring buffer: %s", strerror(errno));
        err = 1;
        goto cleanup;
    }

    /* Daemonize if requested (after BPF setup so errors are visible) */
    if (cfg.daemon_mode) {
        LOG_INFO("Entering daemon mode");
        if (daemonize() < 0) {
            err = 1;
            goto cleanup;
        }
    }

    /* Print header for text mode */
    if (!cfg.json_output && !cfg.daemon_mode) {
        printf("%-8s %-8s %-17s  %-15s      %-17s  %-15s\n",
               "TIME", "TYPE", "SENDER MAC", "SENDER IP",
               "TARGET MAC", "TARGET IP");
        printf("──────── ──────── ─────────────────  "
               "───────────────  ->  ─────────────────  ───────────────\n");
    }

    LOG_INFO("Monitoring started. Press Ctrl+C to stop.");

    /* Main event loop */
    while (!exiting) {
        err = ring_buffer__poll(rb, 100);
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            LOG_ERR("Error polling ring buffer: %s", strerror(-err));
            break;
        }
    }

    LOG_INFO("Shutting down (processed %lu events, %lu spoof alerts, "
             "%lu table resets)",
             (unsigned long)detector.total_events,
             (unsigned long)detector.spoof_alerts,
             (unsigned long)detector.table_resets);

cleanup:
    /* Detach XDP program */
    if (cfg.ifindex > 0)
        bpf_xdp_detach(cfg.ifindex, 0, NULL);

    /* Free ring buffer */
    ring_buffer__free(rb);

    /* Destroy BPF skeleton (closes all FDs, frees maps) */
    arp_monitor_bpf__destroy(skel);

    /* Remove PID file if we created one */
    if (cfg.daemon_mode)
        unlink(PID_FILE);

    /* Flush output */
    fflush(stdout);
    fflush(stderr);

    /* Cleanup logging */
    log_cleanup();

    return err < 0 ? 1 : err;
}
