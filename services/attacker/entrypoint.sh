#!/bin/bash

set -eu

# Give time for web, promtail, loki, grafana, ids to come up
sleep 15

# Target host and port; fall back to docker‑compose service names
TARGET_HOST="${TARGET_HOST:-web}"
TARGET_PORT="${TARGET_PORT:-80}"

echo "Attacker started; targeting $TARGET_HOST:$TARGET_PORT"

# Light SYN flood burst (short)
# Requires NET_RAW; targets "web" service on 80
hping3 -S -p 80 --faster --count 800 web || true

# Quick port scan
nmap -Pn -sS -T4 -p 1-1024 web || true

# Some normal HTTP traffic (benign)
ab -n 200 -c 10 http://web/ || true

# Keep sending a little noise every minute
while :; do
  curl -s http://web/ >/dev/null || true
  sleep 60
done
