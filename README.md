# Network Traffic Anomaly Detection (Isolation Forest)

An end‑to‑end, container‑ready Intrusion / Anomaly Detection playground built around:

* Flow aggregation (bidirectional, canonical 5‑tuple) from packets (live or PCAP)
* Feature engineering (packet/byte counts, statistics, timings, TCP flags)
* Isolation Forest model training (with optional label‑aware contamination calibration & synthetic outliers)
* Multiple data preparation utilities (live capture, PCAP → flows, synthetic data generator, CSE‑CIC‑IDS 2018 normaliser)
* Real‑time detection with structured logging + alerts CSV
* Observability stack (Loki + Promtail + Grafana) to visualise alerts
* Reproducible Docker Compose demo including: victim web server, detector, attack traffic generator, monitoring stack

Everything is packaged as an installable Python module (`ids-iforest`) exposing convenient console scripts.

---

## 1. Repository Layout

```
ids_iforest_package/       Python package (pyproject.toml, source code)
  ids_iforest/
   utils.py               Core utilities (config, logging, flow aggregation, model IO)
   train.py               Train Isolation Forest
   detect.py              Live / CSV / PCAP detection (writes alerts.csv)
   capture.py             Live capture → flows CSV (for building datasets)
   pcap2flows.py          Offline PCAP → flows CSV
   server.py              (Optional) Flask UI (not enabled by default entry points)
   scripts/
    generate_datasets.py Synthetic benign + SYN flood + port scan data
    prepare_csecic2018.py Curate CSE‑CIC‑IDS 2018 CSVs → unified feature set
config/                    Default YAML config (window, iface, paths...)
models/                    Pre‑trained model(s) + thresholds.json + model cards
logs/                      Runtime logs + alerts.csv (for monitoring)
data/                      Example raw & processed datasets
docker-compose.yml         Orchestrates demo & monitoring stack
attacker/                  Traffic generator container (wrk + hping3)
ids/                       IDS service Dockerfile & entrypoint
web/                       Minimal Nginx victim site (port 8080)
monitoring/                Loki / Promtail / Grafana provisioning
tests/                     Pytest unit tests (dataset + training/detection)
```

---

## 2. Core Concepts & Data Flow

```
        (live packets)    (PCAP)               (synthetic / prepared CSV)
            │             │                             │
    capture.py ──┴─┐       pcap2flows.py                  generate_datasets.py
              │                prepare_csecic2018.py (optional real dataset)
              ▼
          Flows CSV  ──► train.py ──► model (.joblib) + thresholds.json
                            │
                  detect.py ◄──┴── (live / CSV / PCAP) → alerts.csv + logs
                            │
                     Promtail → Loki → Grafana dashboard
```

Key feature sets: `minimal` or (default) `extended` (adds TCP flag counts, IAT statistics, per‑packet & per‑second rates).

---

## 3. Installation (Local Development)

Prerequisites: Python 3.10 – 3.13 (PyShark requires a working `tshark`), `pip`.

```
pip install -e ids_iforest_package
```

Installed console scripts (from `pyproject.toml`):

* `ids-iforest-train` – train model
* `ids-iforest-detect` – run detection (live / CSV / PCAP)
* `ids-iforest-capture` – capture live traffic to flows CSV (optionally labelled)
* `ids-iforest-pcap2csv` – convert a PCAP to flows CSV
* `ids-iforest-generate` – synthetic dataset generator

Note: `server.py` (Flask UI) exists but its entry point is commented out; monitoring now uses Grafana. You can still run it manually: `python -m ids_iforest.server`.

Install `tshark` (Ubuntu/Debian): `sudo apt install tshark` (needs permission to capture, e.g. add user to `wireshark` group or run with capabilities).

---

## 4. Quick Start (Local)

1. Generate synthetic training data:
  ```
  ids-iforest-generate --benign 1000 --syn-flood 200 --port-scan 200 --out data/train.csv
  ```

2. Train a model:
  ```
  ids-iforest-train --csv data/train.csv --config config/config.yml --out models
  ```
  Produces: `models/ids_iforest_<git>.joblib`, `ids_iforest_latest.joblib`, `thresholds.json`, `model_card_<hash>.json`.

3. Run detection on the same CSV (offline):
  ```
  ids-iforest-detect --csv data/train.csv --config config/config.yml
  ```

4. Run live detection (captures packets on configured interface):
  ```
  ids-iforest-detect --config config/config.yml
  ```

5. Convert a PCAP to flows then detect:
  ```
  ids-iforest-pcap2csv --pcap capture.pcap --out flows.csv
  ids-iforest-detect --csv flows.csv --config config/config.yml
  ```

6. Capture your own benign flows for future training:
  ```
  ids-iforest-capture --minutes 5 --out benign.csv --label 0
  ```

Alerts will append to `logs/alerts.csv` and log files `logs/detect.log`, etc.

---

## 5. Configuration (`config/config.yml`)

Example (current default):
```yaml
window_seconds: 10          # Flow aggregation window size
bpf_filter: "tcp or udp"     # Berkeley Packet Filter for capture
feature_set: extended       # 'minimal' or 'extended'
contamination: 0.02         # Default contamination (may be overridden by calibration)
model_dir: /app/models      # Can be relative or absolute
logs_dir: /app/logs
iface: "any"                # Interface for live capture (e.g. eth0, any)
```
Path resolution & fallbacks (implemented in `utils.load_config`):
1. Read YAML (apply defaults if keys missing)
2. Override with environment variables `IDS_MODEL_DIR`, `IDS_LOGS_DIR` if set
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

Thresholds: `thresholds.json` contains `red_threshold` & `yellow_threshold` (yellow defaults to 0.0). `detect.py` marks flows with score < yellow as anomalies; `< red` = RED else YELLOW.

---

## 6. Training Details

* Features scaled with `StandardScaler`.
* Optional contamination calibration: grid search over `[0.005, 0.01, 0.02, 0.05]` using F1 on validation if labels present.
* Synthetic outlier injection (default 2%) pushes model to assign lower scores to extreme values.
* Model + scaler stored together (joblib dict). Latest symlink file: `ids_iforest_latest.joblib`.
* Threshold heuristic: if labels present → 1st percentile of benign scores; else min(score) − 0.05.
* Model card records git hash, feature set, contamination default, feature columns.

---

## 7. Detection Modes

`ids-iforest-detect` chooses mode by arguments:
* `--csv <flows.csv>`: score existing flow rows
* `--pcap <file.pcap>`: stream PCAP packets, aggregate per window, score
* (no file args): live capture on `iface`

Outputs:
* Logs: `logs/detect.log` (colour in console if `colorama` installed)
* Alerts CSV: `logs/alerts.csv` columns: `timestamp,src_ip,dst_ip,src_port,dst_port,protocol,score,level`

---

## 8. Preparing Real Dataset (CSE‑CIC‑IDS 2018)

Use the helper normaliser (handles column name variants, merges direction counts, converts microseconds → seconds, derives expected features):
```
python -m ids_iforest.scripts.prepare_csecic2018 \
  --in_glob "data/raw/csecic2018/*TrafficForML_CICFlowMeter.csv" \
  --out_csv data/processed/csecic2018_small.csv \
  --limit 500000   # optional row limit
```
Then train on the resulting CSV.

---

## 9. Synthetic Dataset Generator

`ids-iforest-generate` creates benign + SYN flood + port scan flows with a `label` column (0 benign / 1 attack). Handy for quick tests & CI.

---

## 10. Docker & Monitoring Stack

`docker-compose.yml` services:
* `web` – Nginx victim (port 8080 host)
* `ids` – Detector container (shares network namespace of `web` so `tshark` sees intra‑container traffic). Runs `ids-iforest-detect` (not Flask UI) via `ids/entrypoint.sh`. If no model is present it auto‑generates synthetic dataset & trains (requires writable `/app/models`). In the provided compose file `./models:/app/models:ro` is mounted read‑only: supply a pre‑trained model locally or remove `:ro` to allow training inside container.
* `attacker` – Generates benign HTTP load (wrk) and intermittent SYN floods (hping3)
* `loki` + `promtail` + `grafana` – Observability stack. `promtail` tails `logs/alerts.csv` → Loki → Grafana dashboard (`monitoring/grafana/dashboards/mini-ids.json`). Grafana port: 3000 (anonymous viewer enabled)

Run demo:
```
docker compose build
docker compose up
```
Visit:
* Victim web: http://localhost:8080
* Grafana:    http://localhost:3000 (admin/admin if login needed)

Stop:
```
docker compose down
```

Privileges: Packet capture needs capabilities. The `ids` container adds `NET_ADMIN` & `NET_RAW` so `tshark` can sniff.

---

## 11. Optional Flask UI (Legacy)

`ids_iforest/server.py` can run a lightweight web page listing alerts (port 5000). Not enabled by default. To try:
```
python -m ids_iforest.server --config config/config.yml
```
Or re‑enable in `pyproject.toml` by adding:
```
ids-iforest-server = "ids_iforest.server:main"
```

---

## 12. Testing

Pytest tests cover synthetic dataset generation and a minimal train→detect cycle. After editable install:
```
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

pre-commit run end-of-file-fixer --files <PATH to the file causing issues>
pre-commit run --all-files

git push --no-verify

(Get-Content -Raw ids_iforest_package\pytest.ini) -replace "`r`n", "`n" | Set-Content -NoNewline ids_iforest_package\pytest.ini

# debug quicly why not generating alert json
docker exec -it ids_iforest /bin/bash
ids-iforest-generate --benign 50 --syn-flood 20 --port-scan 20 --out /tmp/synthetic.csv
ids-iforest-detect --csv /tmp/synthetic.csv --config /app/config/config.yml --alerts-csv /app/logs/alerts.csv
ls -l /app/logs
echo "Last alerts:"; tail -n 5 /app/logs/alerts.jsonl || true
cat /app/logs/alerts.jsonl


# How to trigger publish_to_pypi
Keeping with standard release practice, the job runs on tags.
```bash
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```
