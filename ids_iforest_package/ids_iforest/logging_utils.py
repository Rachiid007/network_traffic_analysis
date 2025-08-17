import os
import json
import datetime
from typing import Dict, Any

def append_json_alert(jsonl_path: str, **alert_data: Any) -> None:
    """
    Append an alert to the JSONL file with proper formatting for Loki/Grafana.

    Args:
        jsonl_path: Path to the JSONL file
        **alert_data: Alert data fields (score, src_ip, etc.)
    """
    # Ensure directory exists
    os.makedirs(os.path.dirname(jsonl_path), exist_ok=True)

    # Add timestamp if not present
    if "timestamp" not in alert_data:
        alert_data["timestamp"] = datetime.datetime.now().isoformat()

    # Convert numeric types to strings for JSON serialization
    for k, v in alert_data.items():
        if isinstance(v, float):
            alert_data[k] = float(v)  # Ensure proper float formatting

    try:
        with open(jsonl_path, "a") as f:
            json_line = json.dumps(alert_data)
            f.write(json_line + "\n")
            f.flush()  # Force write to disk
    except Exception as e:
        print(f"Error writing alert to {jsonl_path}: {e}")
