/* SPDX-License-Identifier: MIT */
#ifndef SPOOF_DETECT_H
#define SPOOF_DETECT_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>

#define SPOOF_TABLE_SIZE 1024
#define DEFAULT_FLIP_THRESHOLD 3

/* Userspace ARP entry tracking */
struct spoof_entry {
    uint32_t ip;
    uint8_t mac[6];
    uint32_t flip_count;
    time_t first_seen;
    time_t last_seen;
    bool in_use;
};

/* Whitelist entry */
struct whitelist_entry {
    uint32_t ip;
    uint8_t mac[6];
    bool in_use;
};

struct spoof_detector {
    struct spoof_entry table[SPOOF_TABLE_SIZE];
    struct whitelist_entry whitelist[64];
    int whitelist_count;
    uint32_t flip_threshold;
    uint64_t total_events;
    uint64_t spoof_alerts;
    uint64_t table_resets;
};

/* Result of checking an ARP event */
enum spoof_result {
    SPOOF_OK = 0,      /* Normal ARP traffic */
    SPOOF_NEW_HOST,    /* First time seeing this IP */
    SPOOF_MAC_CHANGED, /* MAC changed (below threshold) */
    SPOOF_ALERT,       /* Spoofing alert (above threshold) */
    SPOOF_WHITELISTED, /* IP-MAC pair is whitelisted */
};

static inline void spoof_detector_init(struct spoof_detector *sd, uint32_t flip_threshold)
{
    memset(sd, 0, sizeof(*sd));
    sd->flip_threshold = flip_threshold > 0 ? flip_threshold : DEFAULT_FLIP_THRESHOLD;
}

static inline int spoof_add_whitelist(struct spoof_detector *sd, uint32_t ip, const uint8_t mac[6])
{
    if (sd->whitelist_count >= 64)
        return -1;
    struct whitelist_entry *we = &sd->whitelist[sd->whitelist_count];
    we->ip = ip;
    memcpy(we->mac, mac, 6);
    we->in_use = true;
    sd->whitelist_count++;
    return 0;
}

static inline bool spoof_is_whitelisted(const struct spoof_detector *sd, uint32_t ip,
                                        const uint8_t mac[6])
{
    for (int i = 0; i < sd->whitelist_count; i++) {
        if (sd->whitelist[i].in_use && sd->whitelist[i].ip == ip &&
            memcmp(sd->whitelist[i].mac, mac, 6) == 0)
            return true;
    }
    return false;
}

static inline uint32_t spoof_hash_ip(uint32_t ip)
{
    /* Simple hash for IPv4 */
    return ((ip >> 16) ^ ip) % SPOOF_TABLE_SIZE;
}

static inline struct spoof_entry *spoof_find_entry(struct spoof_detector *sd, uint32_t ip)
{
    uint32_t idx = spoof_hash_ip(ip);
    /* Linear probing */
    for (uint32_t i = 0; i < SPOOF_TABLE_SIZE; i++) {
        uint32_t pos = (idx + i) % SPOOF_TABLE_SIZE;
        if (!sd->table[pos].in_use)
            return NULL;
        if (sd->table[pos].ip == ip)
            return &sd->table[pos];
    }
    return NULL;
}

static inline struct spoof_entry *spoof_get_or_create(struct spoof_detector *sd, uint32_t ip)
{
    uint32_t idx = spoof_hash_ip(ip);
    struct spoof_entry *first_free = NULL;

    for (uint32_t i = 0; i < SPOOF_TABLE_SIZE; i++) {
        uint32_t pos = (idx + i) % SPOOF_TABLE_SIZE;
        if (!sd->table[pos].in_use) {
            if (!first_free)
                first_free = &sd->table[pos];
            break;
        }
        if (sd->table[pos].ip == ip)
            return &sd->table[pos];
    }

    /*
     * Table full — possible ARP flood attack trying to exhaust tracking.
     * Reset the entire table to recover. Linear probing means we cannot
     * safely evict a single entry without breaking probe chains.
     */
    if (!first_free) {
        sd->table_resets++;
        memset(sd->table, 0, sizeof(sd->table));
        first_free = &sd->table[spoof_hash_ip(ip)];
    }

    first_free->ip = ip;
    first_free->in_use = true;
    first_free->flip_count = 0;
    first_free->first_seen = time(NULL);
    first_free->last_seen = first_free->first_seen;
    return first_free;
}

static inline enum spoof_result spoof_check(struct spoof_detector *sd, uint32_t ip,
                                            const uint8_t mac[6])
{
    sd->total_events++;

    if (spoof_is_whitelisted(sd, ip, mac))
        return SPOOF_WHITELISTED;

    struct spoof_entry *entry = spoof_find_entry(sd, ip);

    if (!entry) {
        /* New host */
        entry = spoof_get_or_create(sd, ip);
        if (entry) {
            memcpy(entry->mac, mac, 6);
            entry->first_seen = time(NULL);
            entry->last_seen = entry->first_seen;
        }
        return SPOOF_NEW_HOST;
    }

    entry->last_seen = time(NULL);

    /* Same MAC as before — normal */
    if (memcmp(entry->mac, mac, 6) == 0)
        return SPOOF_OK;

    /* MAC changed */
    entry->flip_count++;
    memcpy(entry->mac, mac, 6);

    if (entry->flip_count >= sd->flip_threshold) {
        sd->spoof_alerts++;
        return SPOOF_ALERT;
    }

    return SPOOF_MAC_CHANGED;
}

#endif /* SPOOF_DETECT_H */
