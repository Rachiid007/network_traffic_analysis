import os
import json
import datetime
from typing import Any


def append_json_alert(jsonl_path: str, **alert_data: Any) -> None:
    """
    Append an alert to the JSONL file (one JSON object per line) for Promtail/Loki.
    """
    os.makedirs(os.path.dirname(jsonl_path), exist_ok=True)

    if "timestamp" not in alert_data:
        alert_data["timestamp"] = datetime.utcnow().isoformat() + "Z"

    # Ensure pure-Python types for JSON (avoid numpy scalars)
    for k, v in list(alert_data.items()):
        if isinstance(v, float):
            alert_data[k] = float(v)
        elif isinstance(v, int):
            alert_data[k] = int(v)

    try:
        with open(jsonl_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert_data) + "\n")
            f.flush()  # best-effort real-time tailing
    except Exception as e:
        # Fall back to stderr; don't crash the detector
        print(f"[ids-iforest] Error writing alert to {jsonl_path}: {e}")
