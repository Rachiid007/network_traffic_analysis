# Network Traffic Anomaly Detection (Isolation Forest)

An end‑to‑end, container‑ready Intrusion Detection System (IDS) built around Isolation Forest algorithm for anomaly-based detection of network attacks.

---

## 1. Repository Layout

```
├── config/                  # Configuration files
│   └── config.yml           # Main configuration for the IDS
├── data/                    # Training and test data
│   ├── train.csv            # Synthetic or real training data
│   ├── processed/           # Preprocessed datasets
│   └── raw/                 # Original raw data files
├── ids_iforest_package/     # Main Python package
│   ├── ids_iforest/         # Core modules
│   │   ├── scripts/         # Helper scripts
│   │   └── ...              # Core modules (train.py, detect.py, etc.)
│   ├── tests/               # Unit and integration tests
│   └── pyproject.toml       # Package metadata and dependencies
├── logs/                    # Log files directory
│   ├── alerts.csv           # Generated alerts
│   ├── detect.log           # Detection process logs
│   └── train.log            # Training process logs
├── models/                  # Trained models directory
│   ├── ids_iforest_latest.joblib  # Latest model symlink
│   ├── ids_iforest_<hash>.joblib  # Versioned model files
│   └── thresholds.json      # Alert thresholds
├── services/                # Docker service definitions
│   ├── attacker/            # Attack simulation container
│   ├── ids/                 # IDS container => will run the [PyPi local module](./ids_iforest_package/pyproject.toml)
│   ├── web/                 # Victim web server
│   └── monitoring/          # Grafana, Loki, Promtail stack
└── docker-compose.yml       # Multi-container orchestration
```

---

## 2. Core Concepts & Data Flow

```
1. Packet Capture → 2. Flow Aggregation → 3. Feature Extraction →
4. Anomaly Detection → 5. Alert Generation → 6. Visualization
```

1. **Packet Capture**: Live traffic is captured using PyShark/tshark with configurable BPF filters.
2. **Flow Aggregation**: Packets are aggregated into bi-directional flows within time windows.
3. **Feature Extraction**: Features like packet counts, bytes, duration, TCP flags, IAT statistics are calculated.
4. **Anomaly Detection**: Isolation Forest model scores flows (0-1), with lower scores indicating anomalies.
5. **Alert Generation**: Flows with scores below thresholds trigger alerts written to logs/alerts.csv.
6. **Visualization**: Grafana dashboard displays alerts and traffic patterns via Loki.

Key feature sets: `minimal` or (default) `extended` (adds TCP flag counts, IAT statistics, per‑packet & per‑second rates).

---

## 3. Installation (Local Development)

Prerequisites: Python 3.10 – 3.13 (PyShark requires a working `tshark`), `pip`.

```bash
pip install -e ids_iforest_package
```

Installed console scripts (from `pyproject.toml`):

* `ids-iforest-train` – Train model on flow CSV data with optional contamination calibration
* `ids-iforest-detect` – Run detection on live traffic, PCAP file, or flow CSV
* `ids-iforest-capture` – Capture live traffic to flows CSV (with optional labeling)
* `ids-iforest-pcap2csv` – Convert a PCAP file to flows CSV format
* `ids-iforest-generate` – Generate synthetic datasets for testing

Note: `server.py` (Flask UI) exists but its entry point is commented out; monitoring now uses Grafana. You can still run it manually: `python -m ids_iforest.server`.

Install `tshark` (Ubuntu/Debian): `sudo apt install tshark` (needs permission to capture, e.g. add user to `wireshark` group or run with capabilities).

---

## 4. Quick Start (Local)

1. Generate synthetic training data:
  ```bash
  ids-iforest-generate --benign 1000 --syn-flood 200 --port-scan 200 --out data/train.csv
  ```
  This creates a labeled dataset with both normal traffic and attack patterns.

2. Train a model:
  ```bash
  ids-iforest-train --csv data/train.csv --config config/config.yml --out models
  ```
  Produces:
  - `models/ids_iforest_<git_hash>.joblib` - Versioned model
  - `models/ids_iforest_latest.joblib` - Symlink to latest model
  - `thresholds.json` - Detection thresholds
  - `model_card_<hash>.json` - Model metadata

3. Run detection on the same CSV (offline):
  ```bash
  ids-iforest-detect --csv data/train.csv --config config/config.yml
  ```

4. Run live detection (captures packets on configured interface):
  ```bash
  ids-iforest-detect --config config/config.yml
  ```

5. Convert a PCAP to flows then detect:
  ```bash
  ids-iforest-pcap2csv --pcap capture.pcap --out flows.csv
  ids-iforest-detect --csv flows.csv --config config/config.yml
  ```

6. Capture your own benign flows for future training:
  ```bash
  ids-iforest-capture --minutes 5 --out benign.csv --label 0
  ```

Alerts will append to `logs/alerts.csv` and log files `logs/detect.log`, etc.

---

## 5. Configuration (`config/config.yml`)

Example (current default):
```yaml
window_seconds: 10          # Flow aggregation window size
bpf_filter: "tcp or udp"    # Berkeley Packet Filter for capture
feature_set: extended       # 'minimal' or 'extended'
contamination: 0.02         # Default contamination (may be overridden by calibration)
model_dir: /app/models      # Can be relative or absolute
logs_dir: /app/logs         # Logs directory path
iface: "any"                # Interface for live capture (e.g. eth0, any)
```

Path resolution & fallbacks (implemented in `utils.load_config`):
1. Read YAML (apply defaults if keys missing)
2. Override with environment variables `IDS_MODEL_DIR`, `IDS_LOGS_DIR`, `IFACE` if set
3. Resolve relative paths relative to the config file location
4. Test writability. If not writable, try (first that works):
  * `/app/models` or `/app/logs` (inside container)
  * `<CWD>/models` or `<CWD>/logs`
  * `~/.ids_iforest/models` or `~/.ids_iforest/logs`
5. Records chosen fallback under `_path_fallbacks` key in returned config

Environment overrides (bash / *nix):
```
export IDS_MODEL_DIR=/absolute/path/to/models
export IDS_LOGS_DIR=/absolute/path/to/logs
```

Thresholds: `thresholds.json` contains `red_threshold` & `yellow_threshold` (yellow defaults to 0.0). `detect.py` marks flows with score < yellow as anomalies; `< red` = RED alert else YELLOW alert.

---

## 6. Training Details

* Features scaled with `StandardScaler` to normalize values across different scales.
* Optional contamination calibration: grid search over `[0.005, 0.01, 0.02, 0.05]` using F1 on validation if labels present.
* Synthetic outlier injection (default 2%) pushes model to assign lower scores to extreme values.
* Model + scaler stored together in a joblib dictionary. Latest symlink file: `ids_iforest_latest.joblib`.
* Threshold heuristic:
  - If labels present → 1st percentile of benign scores
  - Otherwise → min(score) - 0.05
* Model card records git hash, feature set, contamination default, feature columns.

---

## 7. Detection Modes

`ids-iforest-detect` chooses mode by arguments:
* `--csv <flows.csv>`: Score existing flow rows from a CSV file
* `--pcap <file.pcap>`: Stream PCAP packets, aggregate per window, score
* (no file args): Live capture on configured `iface` from config.yml

Outputs:
* Logs: `logs/detect.log` (color-coded in console if `colorama` installed)
* Alerts CSV: `logs/alerts.csv` with columns:
  `timestamp,src_ip,dst_ip,src_port,dst_port,protocol,score,level`
* Alerts JSON: `logs/alerts.jsonl` (for Grafana/Loki ingestion)

---

## 8. Preparing Real Dataset (CSE‑CIC‑IDS 2018)

Use the helper normaliser script to prepare this standard dataset for training:
```bash
python -m ids_iforest.scripts.prepare_csecic2018 \
  --in_glob "data/raw/csecic2018/*TrafficForML_CICFlowMeter.csv" \
  --out_csv data/processed/csecic2018_processed.csv \
  --limit 500000   # optional row limit
```

This script handles:
- Column name variants
- Merges direction counts
- Converts microseconds → seconds
- Derives expected features

Then train on the resulting CSV as normal.

---

## 9. Synthetic Dataset Generator

`ids-iforest-generate` creates realistic flow data with the following characteristics:

* **Benign flows**: Normal packet counts, bytes, and timing
* **SYN-flood flows**: Extremely high packet rates with TCP SYN flags
* **Port scan flows**: Many flows with minimal packets per destination port

All generated flows include a `label` column (0 for benign, 1 for attack) for training and evaluation.

---

## 10. Docker & Monitoring Stack

`docker-compose.yml` services:

* **web**: Nginx victim web server (exposed on port 8080)
* **ids_iforest**: Detector container that:
  - Shares network namespace with `web` (sees all container traffic)
  - Runs `ids-iforest-detect` via `services/ids/entrypoint.sh`
  - Auto-generates synthetic data & trains if no model exists
  - Mounts `./models:/app/models` (read-only by default)
  - Has special capabilities (`NET_ADMIN`, `NET_RAW`) for packet capture
* **attacker**: Attack simulation container that:
  - Generates benign HTTP traffic with Apache Bench (`ab`)
  - Performs SYN floods with `hping3`
  - Conducts port scans with `nmap`
* **loki + promtail + grafana**: Observability stack where:
  - `promtail` tails `logs/alerts.csv` → `loki` → `grafana`
  - Grafana dashboard in `monitoring/grafana/dashboards/mini-ids.json`
  - Grafana port: 3000 (anonymous viewer enabled)

Run the demo:
```bash
docker compose build
docker compose up
```

Visit:
* Victim web server: http://localhost:8080
* Grafana dashboard: http://localhost:3000 (admin/admin if login needed)

Stop:
```bash
docker compose down
```

---

## 11. PyPI Package Structure

The `ids_iforest_package` contains the following key modules:

* **train.py**: Implements model training with contamination calibration
* **detect.py**: Core detection engine for all three modes (live/PCAP/CSV)
* **capture.py**: Captures traffic to flows CSV for training data collection
* **pcap2flows.py**: Converts PCAP files to flows CSV format
* **utils.py**: Common utilities for configuration, logging, and flow processing
* **scripts/generate_datasets.py**: Synthetic data generator
* **scripts/prepare_csecic2018.py**: Preprocessor for CIC-IDS 2018 dataset

Command-line tools in `pyproject.toml`:
```toml
[project.scripts]
ids-iforest-train   = "ids_iforest.train:main"
ids-iforest-detect  = "ids_iforest.detect:main"
ids-iforest-capture = "ids_iforest.capture:main"
ids-iforest-pcap2csv= "ids_iforest.pcap2flows:main"
ids-iforest-generate= "ids_iforest.scripts.generate_datasets:main"
```

## 12. Testing

Pytest tests cover synthetic dataset generation and a minimal train→detect cycle. After editable install:
```bash
pytest -q
```

---

## 13. Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| `RuntimeError: pyshark is not installed` | Install package extras or ensure dependency installed (it is in `pyproject.toml`). |
| `No model found in <dir>` | Run training first or provide mounted model (ids_iforest_latest.joblib). |
| Permission errors writing models/logs | Adjust `model_dir` / `logs_dir`, remove `:ro` in compose, or set `IDS_MODEL_DIR` / `IDS_LOGS_DIR`. |
| Empty alerts | Thresholds maybe too low; inspect `thresholds.json`, or generate more attack data. |
| High false positives | Re‑train with labels to calibrate contamination or reduce synthetic outlier ratio in `train.py`. |

---

## 14. Limitations & Future Ideas

* Single‑threaded detection loop (adequate for demo; could batch or parallelise)
* Basic feature set (can add flow directionality, entropy, TLS metadata, etc.)
* Simple thresholds (could adopt adaptive / quantile drift tracking)
* No persistence for alerts beyond CSV (Grafana dashboard uses Loki ingestion only)
* Model explainability not implemented (Shapley, feature attributions)

---

## 15. License

MIT – see `LICENSE`.

---

## 16. Attribution

Author: Rachid Bellaali. Isolation Forest, PyShark, Loki, Grafana are respective upstream projects; datasets like CSE‑CIC‑IDS 2018 belong to their creators.

Happy experimenting & learning! 🚀
