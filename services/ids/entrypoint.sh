#!/usr/bin/env bash
set -euo pipefail

# Be explicit about the interface your code already defaults to ("eth0")
# and use your existing config/config.yml
echo "[ids] starting ids-iforest live capture..."
exec ids-iforest-detect --config /app/config/config.yml
