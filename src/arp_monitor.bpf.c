// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * arp_monitor.bpf.c — eBPF/XDP program for ARP packet monitoring
 *
 * Captures ARP packets at the XDP hook, copies relevant fields into a
 * ring buffer event, and maintains a per-IP MAC address table for
 * spoofing detection (flip counting done in userspace for simplicity
 * and to avoid verifier complexity with map updates in XDP path).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "../include/arp_monitor.h"

/* Override vmlinux.h ETH_P_ARP if not available */
#define ETH_P_ARP_BE 0x0608  /* ETH_P_ARP (0x0806) in network byte order */

/* ARP header for Ethernet/IPv4 (fixed layout) */
struct arp_ethhdr {
    __be16 ar_hrd;
    __be16 ar_pro;
    __u8   ar_hln;
    __u8   ar_pln;
    __be16 ar_op;
    __u8   ar_sha[6];
    __u8   ar_sip[4];
    __u8   ar_tha[6];
    __u8   ar_tip[4];
} __attribute__((packed));

/* Ring buffer for events to userspace */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

/* Per-CPU counter for dropped events (ring buffer full) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} dropped_events SEC(".maps");

/* Per-IP ARP entry table (for kernel-side tracking, read by userspace) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ARP_ENTRIES);
    __type(key, struct arp_key);
    __type(value, struct arp_entry);
} arp_table SEC(".maps");

SEC("xdp")
int arp_monitor_xdp(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Bounds check: Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    /* Only process ARP packets */
    if (eth->h_proto != ETH_P_ARP_BE)
        return XDP_PASS;

    /* Bounds check: ARP header */
    struct arp_ethhdr *arp = (struct arp_ethhdr *)(eth + 1);
    if ((void *)(arp + 1) > data_end)
        return XDP_PASS;

    /* Only handle Ethernet/IPv4 ARP (hrd=1, pro=0x0800, hln=6, pln=4) */
    if (arp->ar_hln != 6 || arp->ar_pln != 4)
        return XDP_PASS;

    /* Reserve ring buffer slot */
    struct arp_event *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        __u32 key = 0;
        __u64 *cnt = bpf_map_lookup_elem(&dropped_events, &key);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);
        return XDP_PASS;
    }

    /* Fill event */
    e->ar_op = bpf_ntohs(arp->ar_op);
    __builtin_memcpy(e->ar_sha, arp->ar_sha, 6);
    __builtin_memcpy(e->ar_sip, arp->ar_sip, 4);
    __builtin_memcpy(e->ar_tha, arp->ar_tha, 6);
    __builtin_memcpy(e->ar_tip, arp->ar_tip, 4);
    e->ifindex = ctx->ingress_ifindex;

    bpf_ringbuf_submit(e, 0);

    /* Update kernel-side ARP table */
    struct arp_key key = {};
    __builtin_memcpy(&key.ip, arp->ar_sip, 4);

    struct arp_entry new_entry = {};
    __builtin_memcpy(new_entry.mac, arp->ar_sha, 6);
    new_entry.last_seen = bpf_ktime_get_ns() / 1000000000ULL;
    new_entry.flip_count = 0;

    struct arp_entry *existing = bpf_map_lookup_elem(&arp_table, &key);
    if (existing) {
        /* Check if MAC changed */
        if (__builtin_memcmp(existing->mac, arp->ar_sha, 6) != 0) {
            new_entry.flip_count = existing->flip_count + 1;
        } else {
            new_entry.flip_count = existing->flip_count;
        }
    }

    bpf_map_update_elem(&arp_table, &key, &new_entry, BPF_ANY);

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual MIT/GPL";
