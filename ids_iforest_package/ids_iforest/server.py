"""Run a combined detector and web interface for ids_iforest.

This module starts the anomaly detector in a background thread and
exposes a simple Flask web UI to display alerts.  The alerts are
read from the CSV file produced by ``ids_iforest.detect``.  Both
components share the same configuration file.

The web UI shows a table of recent alerts and refreshes every few
seconds.  It is intentionally minimal to keep dependencies light.
"""

from __future__ import annotations

import argparse
import csv
import threading
import time
from pathlib import Path
from typing import List, Dict, Any

from flask import Flask, jsonify, render_template_string

from .utils import load_config, get_logger, load_model, load_thresholds
from .detect import detect_live

__all__ = ["main"]


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>IDS Alerts</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 2em; }
    h1 { color: #333; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
    th { background-color: #f2f2f2; }
    tr.red { background-color: #ffe5e5; }
    tr.yellow { background-color: #fff8e5; }
  </style>
</head>
<body>
  <h1>IDS Alerts</h1>
  <table id="alerts-table">
    <thead>
      <tr>
        <th>Timestamp</th>
        <th>Source IP</th>
        <th>Destination IP</th>
        <th>Src Port</th>
        <th>Dst Port</th>
        <th>Proto</th>
        <th>Score</th>
        <th>Level</th>
      </tr>
    </thead>
    <tbody>
    </tbody>
  </table>
  <script>
    async function fetchAlerts() {
      const resp = await fetch('/alerts.json');
      const data = await resp.json();
      const tbody = document.querySelector('#alerts-table tbody');
      tbody.innerHTML = '';
      data.forEach(row => {
        const tr = document.createElement('tr');
        tr.className = row.level.toLowerCase();
        tr.innerHTML = `
          <td>${row.timestamp}</td>
          <td>${row.src_ip}</td>
          <td>${row.dst_ip}</td>
          <td>${row.src_port}</td>
          <td>${row.dst_port}</td>
          <td>${row.protocol}</td>
          <td>${row.score.toFixed(3)}</td>
          <td>${row.level}</td>
        `;
        tbody.appendChild(tr);
      });
    }
    setInterval(fetchAlerts, 5000);
    fetchAlerts();
  </script>
</body>
</html>
"""


def load_alerts(csv_path: Path) -> List[Dict[str, Any]]:
    """Read the alerts CSV and return a list of dictionaries."""
    if not csv_path.exists():
        return []
    rows: List[Dict[str, Any]] = []
    try:
        with csv_path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Convert numeric fields
                try:
                    row["src_port"] = int(row["src_port"])
                    row["dst_port"] = int(row["dst_port"])
                    row["score"] = float(row["score"])
                except Exception:
                    pass
                rows.append(row)
    except Exception:
        pass
    return rows[-500:]  # Limit to last 500 entries to keep the UI snappy


def run_detector_thread(
    cfg: Dict[str, Any],
    model: Any,
    scaler: Any,
    red_thr: float,
    yellow_thr: float,
    alerts_csv: str,
    logger: Any,
) -> None:
    """Start live detection in a background thread."""
    thread = threading.Thread(
        target=detect_live,
        args=(cfg, model, scaler, red_thr, yellow_thr, logger, alerts_csv),
        daemon=True,
    )
    thread.start()


def main() -> None:
    """Entry point for ids-iforest-server console script.

    This starts the live detector and the Flask web application.
    """
    ap = argparse.ArgumentParser(description="Start IDS detection and web UI")
    ap.add_argument("--config", default="config/config.yml", help="Path to configuration YAML file")
    ap.add_argument(
        "--no-detector", action="store_true", help="Do not start the live detector (UI only)"
    )
    ap.add_argument("--host", default="0.0.0.0", help="Host address for the web server")
    ap.add_argument("--port", type=int, default=5000, help="Port for the web server")
    args = ap.parse_args()
    cfg = load_config(args.config)
    logger = get_logger("server", cfg["logs_dir"], "server.log")
    # Prepare model and thresholds
    model, scaler, _ = load_model(cfg["model_dir"])
    red_thr, yellow_thr = load_thresholds(cfg["model_dir"])
    alerts_csv = Path(cfg["logs_dir"]) / "alerts.csv"
    # Start detector unless disabled
    if not args.no_detector:
        run_detector_thread(cfg, model, scaler, red_thr, yellow_thr, str(alerts_csv), logger)
        logger.info("Live detector started in background thread")
    # Create Flask app
    app = Flask(__name__)

    @app.route("/")
    def index() -> str:
        return render_template_string(HTML_TEMPLATE)

    @app.route("/alerts.json")
    def alerts_json() -> Any:
        data = load_alerts(alerts_csv)
        return jsonify(data)

    logger.info(f"Starting web server on {args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":  # pragma: no cover
    main()
