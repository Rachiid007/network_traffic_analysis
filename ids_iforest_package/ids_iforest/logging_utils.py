import json
import os
import socket
from datetime import datetime, timezone


def append_json_alert(path: str, **alert_fields) -> None:
    """Append alert_fields as a JSON line to `path`."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "host": socket.gethostname(),
        **alert_fields,
    }
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
