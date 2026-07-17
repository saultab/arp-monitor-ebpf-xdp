#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# integration_test.sh — Integration test using veth pair + network namespace
#
# Creates an isolated network namespace, attaches the ARP monitor,
# generates ARP traffic, and verifies the output.
#
# Must be run as root (or with CAP_NET_ADMIN + CAP_BPF).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BINARY="$PROJECT_DIR/arp-monitor"
NS="arp_test_ns"
VETH_HOST="veth-host"
VETH_NS="veth-ns"
OUTPUT_FILE="/tmp/arp_monitor_test_output.json"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

pass() { echo -e "  ${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; FAILURES=$((FAILURES + 1)); }

FAILURES=0
MONITOR_PID=""

cleanup() {
    # Kill monitor if running
    if [[ -n "$MONITOR_PID" ]] && kill -0 "$MONITOR_PID" 2>/dev/null; then
        kill "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
    fi

    # Remove namespace and veth pair
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$VETH_HOST" 2>/dev/null || true
    rm -f "$OUTPUT_FILE"
}
trap cleanup EXIT

# ── Prechecks ───────────────────────────────────────────────────────

echo ""
echo "=== ARP Monitor Integration Tests ==="
echo ""

if [[ $EUID -ne 0 ]]; then
    echo "ERROR: Must be run as root"
    exit 1
fi

if [[ ! -x "$BINARY" ]]; then
    echo "ERROR: Binary not found at $BINARY (run 'make' first)"
    exit 1
fi

# ── Setup ───────────────────────────────────────────────────────────

echo "Setting up test environment..."

# Create namespace
ip netns add "$NS"

# Create veth pair
ip link add "$VETH_HOST" type veth peer name "$VETH_NS"
ip link set "$VETH_NS" netns "$NS"

# Configure addresses
ip addr add 10.0.0.1/24 dev "$VETH_HOST"
ip link set "$VETH_HOST" up

ip netns exec "$NS" ip addr add 10.0.0.2/24 dev "$VETH_NS"
ip netns exec "$NS" ip link set "$VETH_NS" up
ip netns exec "$NS" ip link set lo up

echo "  Host:      $VETH_HOST = 10.0.0.1"
echo "  Namespace: $VETH_NS   = 10.0.0.2"
echo ""

# ── Test 1: Basic ARP capture ──────────────────────────────────────

echo "Test 1: Basic ARP capture (JSON output)"

"$BINARY" -i "$VETH_HOST" -j > "$OUTPUT_FILE" 2>/dev/null &
MONITOR_PID=$!
sleep 1

# Generate ARP traffic (ping triggers ARP)
ip netns exec "$NS" ping -c 1 -W 1 10.0.0.1 >/dev/null 2>&1 || true
sleep 1

# Stop monitor
kill "$MONITOR_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true
MONITOR_PID=""

if [[ -s "$OUTPUT_FILE" ]]; then
    # Check JSON structure
    if grep -q '"type"' "$OUTPUT_FILE" && grep -q '"sender_mac"' "$OUTPUT_FILE"; then
        pass "ARP events captured in JSON format"
    else
        fail "JSON output missing expected fields"
    fi

    if grep -q '"sender_ip":"10.0.0.2"' "$OUTPUT_FILE" || \
       grep -q '"sender_ip":"10.0.0.1"' "$OUTPUT_FILE"; then
        pass "Correct IP addresses in captured events"
    else
        fail "Expected IP addresses not found in output"
    fi
else
    fail "No output captured (file empty)"
fi

# ── Test 2: Spoof detection ────────────────────────────────────────

echo ""
echo "Test 2: ARP spoofing detection"

rm -f "$OUTPUT_FILE"
"$BINARY" -i "$VETH_HOST" -j -t 1 > "$OUTPUT_FILE" 2>/dev/null &
MONITOR_PID=$!
sleep 1

# Send ARP replies with different MACs for the same IP (simulated spoof)
# First: normal ARP from 10.0.0.2
ip netns exec "$NS" ping -c 1 -W 1 10.0.0.1 >/dev/null 2>&1 || true
sleep 0.5

# Change MAC in namespace to simulate spoof
ip netns exec "$NS" ip link set "$VETH_NS" down
ip netns exec "$NS" ip link set dev "$VETH_NS" address 00:de:ad:be:ef:01
ip netns exec "$NS" ip link set "$VETH_NS" up
ip netns exec "$NS" ip addr add 10.0.0.2/24 dev "$VETH_NS" 2>/dev/null || true
sleep 0.5

# Send another ARP from same IP with different MAC
ip netns exec "$NS" ping -c 1 -W 1 10.0.0.1 >/dev/null 2>&1 || true
sleep 1

kill "$MONITOR_PID" 2>/dev/null || true
wait "$MONITOR_PID" 2>/dev/null || true
MONITOR_PID=""

if [[ -s "$OUTPUT_FILE" ]]; then
    if grep -q 'SPOOF_ALERT\|mac_changed' "$OUTPUT_FILE"; then
        pass "Spoofing/MAC change detected"
    else
        fail "Spoof detection did not trigger (may need lower threshold)"
    fi
else
    fail "No output captured for spoof test"
fi

# ── Summary ─────────────────────────────────────────────────────────

echo ""
if [[ $FAILURES -eq 0 ]]; then
    echo -e "${GREEN}All integration tests passed!${NC}"
    exit 0
else
    echo -e "${RED}$FAILURES test(s) failed${NC}"
    exit 1
fi
