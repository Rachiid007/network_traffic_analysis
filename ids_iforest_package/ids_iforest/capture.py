"""Capture live traffic and export aggregated flows to a CSV file for training.

This module provides a simple command‑line tool to sniff packets on a
network interface, aggregate them into bidirectional flows and write
the resulting feature vectors to a CSV file.  It is intended for
gathering benign or malicious training data for the Isolation Forest
model.

Each row in the output CSV corresponds to a flow and contains the
columns defined by ``flows_to_dataframe`` plus an optional ``label``
column.  When ``--label`` is provided, all rows in the dataset will
have that value; otherwise the label column is omitted.

Usage example::

    ids-iforest-capture --minutes 5 --out flows_benign.csv --label 0

"""

from __future__ import annotations

import argparse
import csv
import time
from typing import Optional, Dict, Tuple, Any, Iterable

try:
    import pyshark  # type: ignore
except Exception as exc:  # pragma: no cover
    pyshark = None  # type: ignore

import pandas as pd  # type: ignore

from .utils import (
    load_config,
    get_logger,
    aggregate_packets_to_flows,
    flows_to_dataframe,
)

__all__ = ["main"]


def capture_flows(
    cfg: Dict[str, Any],
    duration_minutes: float,
    logger: Any,
) -> pd.DataFrame:
    """Capture live packets and return aggregated flows as a DataFrame.

    Packets are sniffed on the configured interface using PyShark until
    ``duration_minutes`` elapses.  Flows are aggregated using the
    configured window length and feature set.  At the end of capture
    all flows are converted to a DataFrame and returned.
    """
    if pyshark is None:
        raise RuntimeError("pyshark is not installed – cannot capture packets")
    interface = cfg.get("iface", "eth0")
    bpf_filter = cfg.get("bpf_filter", "tcp or udp")
    window = cfg["window_seconds"]
    feature_set = cfg.get("feature_set", "extended")
    cap = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)
    logger.info(
        f"Beginning capture on {interface} for {duration_minutes} minute(s) with window {window}s"
    )
    flows: Dict[Tuple[int, Tuple[Any, Any, str]], Dict[str, Any]] = {}
    base_ts: Optional[float] = None
    end_time = time.time() + duration_minutes * 60
    try:
        for pkt in cap.sniff_continuously():
            now = time.time()
            if now >= end_time:
                break
            try:
                ts = float(pkt.frame_info.time_epoch)
            except Exception:
                continue
            if base_ts is None:
                base_ts = ts
            # Aggregate this single packet
            f = aggregate_packets_to_flows([pkt], window_seconds=window, base_ts=base_ts)
            for k, st in f.items():
                if k in flows:
                    existing = flows[k]
                    existing["packets"] += st["packets"]
                    existing["bytes"] += st["bytes"]
                    existing["sizes"].extend(st["sizes"])
                    existing["tcp_syn"] += st["tcp_syn"]
                    existing["tcp_fin"] += st["tcp_fin"]
                    existing["tcp_rst"] += st["tcp_rst"]
                    existing["iat"].extend(st["iat"])
                    existing["first_ts"] = min(existing["first_ts"], st["first_ts"])
                    existing["last_ts"] = max(existing["last_ts"], st["last_ts"])
                else:
                    flows[k] = st
    finally:
        cap.close()
    df = flows_to_dataframe(flows, feature_set)
    return df


def write_dataset(df: pd.DataFrame, out_csv: str, label: Optional[int] = None) -> None:
    """Write the aggregated flows DataFrame to a CSV file.

    When ``label`` is provided, a ``label`` column is added with that
    constant value.  The CSV header is always written.
    """
    if label is not None:
        df = df.copy()
        df["label"] = int(label)
    df.to_csv(out_csv, index=False)


def main() -> None:
    """Entry point for ids-iforest-capture console script."""
    ap = argparse.ArgumentParser(description="Capture live packets and aggregate flows for training")
    ap.add_argument("--config", default="config/config.yml", help="Path to configuration YAML file")
    ap.add_argument("--minutes", type=float, default=1.0, help="Duration to capture in minutes")
    ap.add_argument("--out", required=True, help="Output CSV path for the aggregated flows")
    ap.add_argument(
        "--label",
        type=int,
        default=None,
        help="Optional label (0=benign, 1=malicious) to assign to all flows",
    )
    args = ap.parse_args()
    cfg = load_config(args.config)
    logger = get_logger("capture", cfg["logs_dir"], "capture.log")
    df = capture_flows(cfg, args.minutes, logger)
    if df.empty:
        logger.info("No flows captured; dataset will be empty")
    write_dataset(df, args.out, args.label)
    logger.info(f"Captured {len(df)} flows written to {args.out}")


if __name__ == "__main__":  # pragma: no cover
    main()
