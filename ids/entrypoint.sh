#!/bin/bash

# Entrypoint for the IDS container.  This script ensures that a model
# is present; if not, it generates a synthetic dataset and trains one.
# After training, it starts the ids-iforest-server.

set -e

# Directories
MODEL_DIR="/app/models"
LOGS_DIR="/app/logs"
CFG="/app/config/config.yml"

echo "[*] Starting IDS with config: $CFG"
# Helpful: list interfaces to confirm dumpcap can see 'eth0' (not only extcaps)
tshark -D || true

# Ensure directories exist
mkdir -p "$MODEL_DIR" "$LOGS_DIR"

# Check for latest model
MODEL_FILE="$MODEL_DIR/ids_iforest_latest.joblib"
if [ ! -f "$MODEL_FILE" ]; then
  echo "[*] No trained model found; generating synthetic dataset and training"
  DATA_DIR="/app/data"
  mkdir -p "$DATA_DIR"
  DATASET="$DATA_DIR/train.csv"
  # Generate 2000 benign flows and 400 attack flows
  ids-iforest-generate --benign 2000 --syn-flood 200 --port-scan 200 --out "$DATASET"
  # Train model
  ids-iforest-train --csv "$DATASET" --config "$CFG" --out "$MODEL_DIR"
else
  echo "[*] Found existing model $MODEL_FILE"
fi

# Start the web server (which also runs the detector)
exec ids-iforest-server --config "$CFG"