/* SPDX-License-Identifier: MIT */
#ifndef ARP_MONITOR_H
#define ARP_MONITOR_H

#ifdef __BPF_PROGRAM__
/* Types already provided by vmlinux.h — nothing to include */
#elif defined(__KERNEL__)
#include <linux/types.h>
#else
#include <stdint.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
#endif

#define ETH_ALEN        6
#define MAX_ARP_ENTRIES 1024

/* Event passed from BPF program to userspace via ring buffer */
struct arp_event {
    __u16 ar_op;            /* ARP opcode (host byte order) */
    __u8  ar_sha[ETH_ALEN]; /* sender hardware address      */
    __u8  ar_sip[4];        /* sender IP address            */
    __u8  ar_tha[ETH_ALEN]; /* target hardware address      */
    __u8  ar_tip[4];        /* target IP address            */
    __u32 ifindex;          /* ingress interface index       */
};

/* Key for the ARP table map (IP address as u32) */
struct arp_key {
    __u32 ip;
};

/* Value for the ARP table map */
struct arp_entry {
    __u8  mac[ETH_ALEN];    /* last seen MAC for this IP    */
    __u8  _pad[2];          /* alignment padding            */
    __u32 last_seen;        /* timestamp (ktime_ns / 1e9)   */
    __u32 flip_count;       /* number of MAC changes        */
};

#endif /* ARP_MONITOR_H */
