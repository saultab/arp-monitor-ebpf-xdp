/* SPDX-License-Identifier: MIT */
/*
 * test_spoof_detect.c — Unit tests for ARP spoofing detection logic
 *
 * Minimal test framework (no external deps). Run with: make test-unit
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "../src/spoof_detect.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) \
    static void name(void); \
    static void name(void)

#define RUN_TEST(name) do { \
    printf("  %-50s ", #name); \
    tests_run++; \
    name(); \
    tests_passed++; \
    printf("[PASS]\n"); \
} while (0)

#define ASSERT_EQ(a, b) do { \
    if ((a) != (b)) { \
        printf("[FAIL]\n    %s:%d: expected %d, got %d\n", \
               __FILE__, __LINE__, (int)(b), (int)(a)); \
        return; \
    } \
} while (0)

/* ── Tests ──────────────────────────────────────────────────────── */

TEST(test_new_host_detection)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 3);

    uint8_t mac1[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    uint32_t ip = 0x0101A8C0;  /* 192.168.1.1 in little-endian */

    enum spoof_result r = spoof_check(&sd, ip, mac1);
    ASSERT_EQ(r, SPOOF_NEW_HOST);
}

TEST(test_same_mac_is_ok)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 3);

    uint8_t mac1[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    uint32_t ip = 0x0101A8C0;

    spoof_check(&sd, ip, mac1);
    enum spoof_result r = spoof_check(&sd, ip, mac1);
    ASSERT_EQ(r, SPOOF_OK);
}

TEST(test_mac_change_below_threshold)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 3);

    uint8_t mac1[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    uint8_t mac2[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02};
    uint32_t ip = 0x0101A8C0;

    spoof_check(&sd, ip, mac1);
    enum spoof_result r = spoof_check(&sd, ip, mac2);
    ASSERT_EQ(r, SPOOF_MAC_CHANGED);
}

TEST(test_spoof_alert_at_threshold)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 2);  /* Low threshold for testing */

    uint8_t mac1[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    uint8_t mac2[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02};
    uint8_t mac3[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03};
    uint32_t ip = 0x0101A8C0;

    spoof_check(&sd, ip, mac1);  /* NEW_HOST */
    spoof_check(&sd, ip, mac2);  /* MAC_CHANGED (flip_count=1) */
    enum spoof_result r = spoof_check(&sd, ip, mac3);  /* ALERT (flip_count=2) */
    ASSERT_EQ(r, SPOOF_ALERT);
}

TEST(test_whitelist_bypass)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 1);

    uint8_t mac1[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    uint32_t ip = 0x0101A8C0;

    spoof_add_whitelist(&sd, ip, mac1);

    enum spoof_result r = spoof_check(&sd, ip, mac1);
    ASSERT_EQ(r, SPOOF_WHITELISTED);
}

TEST(test_whitelist_does_not_bypass_different_mac)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 3);

    uint8_t mac1[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    uint8_t mac2[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint32_t ip = 0x0101A8C0;

    spoof_add_whitelist(&sd, ip, mac1);

    /* mac2 is NOT whitelisted for this IP */
    enum spoof_result r = spoof_check(&sd, ip, mac2);
    ASSERT_EQ(r, SPOOF_NEW_HOST);
}

TEST(test_multiple_ips_independent)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 3);

    uint8_t mac1[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    uint8_t mac2[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02};
    uint32_t ip1 = 0x0101A8C0;
    uint32_t ip2 = 0x0201A8C0;

    spoof_check(&sd, ip1, mac1);
    spoof_check(&sd, ip2, mac2);

    enum spoof_result r1 = spoof_check(&sd, ip1, mac1);
    enum spoof_result r2 = spoof_check(&sd, ip2, mac2);
    ASSERT_EQ(r1, SPOOF_OK);
    ASSERT_EQ(r2, SPOOF_OK);
}

TEST(test_event_counter)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 3);

    uint8_t mac1[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    uint32_t ip = 0x0101A8C0;

    spoof_check(&sd, ip, mac1);
    spoof_check(&sd, ip, mac1);
    spoof_check(&sd, ip, mac1);

    ASSERT_EQ(sd.total_events, 3);
}

TEST(test_spoof_alert_counter)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 1);

    uint8_t mac1[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};
    uint8_t mac2[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02};
    uint32_t ip = 0x0101A8C0;

    spoof_check(&sd, ip, mac1);
    spoof_check(&sd, ip, mac2);  /* flip_count=1 >= threshold=1 → ALERT */

    ASSERT_EQ(sd.spoof_alerts, 1);
}

TEST(test_table_exhaustion_triggers_reset)
{
    struct spoof_detector sd;
    spoof_detector_init(&sd, 3);

    uint8_t mac[] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01};

    /* Fill the table completely */
    for (uint32_t i = 0; i < SPOOF_TABLE_SIZE; i++) {
        uint32_t ip = 0x01000001 + i;  /* 1.0.0.1, 1.0.0.2, ... */
        spoof_check(&sd, ip, mac);
    }
    ASSERT_EQ(sd.table_resets, 0);

    /* Next new IP should trigger a table reset */
    uint32_t overflow_ip = 0x01000001 + SPOOF_TABLE_SIZE;
    enum spoof_result r = spoof_check(&sd, overflow_ip, mac);
    ASSERT_EQ(r, SPOOF_NEW_HOST);
    ASSERT_EQ(sd.table_resets, 1);
}

/* ── Main ───────────────────────────────────────────────────────── */

int main(void)
{
    printf("\n=== ARP Spoof Detection Unit Tests ===\n\n");

    RUN_TEST(test_new_host_detection);
    RUN_TEST(test_same_mac_is_ok);
    RUN_TEST(test_mac_change_below_threshold);
    RUN_TEST(test_spoof_alert_at_threshold);
    RUN_TEST(test_whitelist_bypass);
    RUN_TEST(test_whitelist_does_not_bypass_different_mac);
    RUN_TEST(test_multiple_ips_independent);
    RUN_TEST(test_event_counter);
    RUN_TEST(test_spoof_alert_counter);
    RUN_TEST(test_table_exhaustion_triggers_reset);

    printf("\n  Results: %d/%d passed\n\n", tests_passed, tests_run);

    return (tests_passed == tests_run) ? 0 : 1;
}
