"""Run detection on live traffic, a PCAP or a flows CSV file.

This module provides a command‑line entry point to score network
flows using a previously trained Isolation Forest model.  It supports
three modes of operation:

* Live detection using a capture interface specified in the config.
* Offline detection from a PCAP file (aggregating packets to flows).
* Offline detection from a CSV of flow features (skipping aggregation).

For each flow, the anomaly score is computed via the loaded model and
scaler, and the result is compared against red and yellow thresholds.
Alerts are logged both to stdout and to a CSV file in the logs
directory.  The CSV columns are:

  ``timestamp,src_ip,dst_ip,src_port,dst_port,protocol,score,level``.

The detection loop is intentionally simple – flows are processed
synchronously on the capturing thread.  For higher throughput one
could offload scoring to a worker pool, but this is unnecessary for a
demonstration on modest hardware.
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import os
from typing import Optional, Tuple, Dict, Any, Iterable

import numpy as np  # type: ignore
import pandas as pd  # type: ignore

try:
    import pyshark  # type: ignore
except Exception as exc:  # pragma: no cover - pyshark is an optional dependency
    pyshark = None  # type: ignore

from .utils import (
    load_config,
    get_logger,
    load_model,
    load_thresholds,
    aggregate_packets_to_flows,
    flows_to_dataframe,
    LEVEL_COLOR,
)

__all__ = ["main"]


def _score_flows(
    model: Any,
    scaler: Any,
    df: pd.DataFrame,
    red_thr: float,
    yellow_thr: float,
) -> Iterable[Tuple[str, Dict[str, Any]]]:
    """Score each flow and yield alerts with coloured level strings.

    Parameters
    ----------
    model: Any
        Fitted Isolation Forest.
    scaler: Any
        Fitted StandardScaler.
    df: pandas.DataFrame
        DataFrame of flows including non‑numeric columns.
    red_thr: float
        Threshold below which flows are considered red (severe anomaly).
    yellow_thr: float
        Threshold below which flows are considered yellow (suspicious).

    Yields
    ------
    Tuple[str, Dict[str, Any]]
        (level, alert_data) where alert_data contains timestamp and
        flow metadata.  Only flows whose scores fall below the yellow
        threshold are yielded.
    """
    if df.empty:
        return []  # type: ignore
    # Select numeric columns for the scaler/model
    numeric_cols = [
        "bidirectional_packets",
        "bidirectional_bytes",
        "mean_packet_size",
        "std_packet_size",
        "flow_duration",
    ]
    # extended columns if present
    extended = [
        "tcp_syn_count",
        "tcp_fin_count",
        "tcp_rst_count",
        "iat_mean",
        "iat_std",
        "bytes_per_packet",
        "packets_per_second",
    ]
    for col in extended:
        if col in df.columns:
            numeric_cols.append(col)
    X = scaler.transform(df[numeric_cols].fillna(0.0).astype(float).values)
    scores = model.decision_function(X)
    now_str = _dt.datetime.utcnow().isoformat()
    for idx, score in enumerate(scores):
        score_f = float(score)
        if score_f < yellow_thr:
            level = "RED" if score_f < red_thr else "YELLOW"
            row = df.iloc[idx]
            alert = {
                "timestamp": now_str,
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "src_port": int(row["src_port"]),
                "dst_port": int(row["dst_port"]),
                "protocol": row["protocol"],
                "score": score_f,
                "level": level,
            }
            yield level, alert


def _write_alert_csv(alerts: Iterable[Tuple[str, Dict[str, Any]]], csv_path: str) -> None:
    """Append alert rows to the CSV file designated by ``csv_path``.

    The CSV is created on first use and includes a header row.
    """
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)
    exists = os.path.exists(csv_path)
    with open(csv_path, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp",
                "src_ip",
                "dst_ip",
                "src_port",
                "dst_port",
                "protocol",
                "score",
                "level",
            ],
        )
        if not exists:
            writer.writeheader()
        for _, alert in alerts:
            writer.writerow(alert)


def _process_dataframe(
    df: pd.DataFrame,
    model: Any,
    scaler: Any,
    red_thr: float,
    yellow_thr: float,
    logger: Any,
    csv_path: str,
) -> None:
    """Score flows in ``df`` and log any anomalies.

    Both the logger and the alerts CSV are updated.  Anomalous flows
    trigger colourised log output.
    """
    alerts = list(_score_flows(model, scaler, df, red_thr, yellow_thr))
    for level, alert in alerts:
        colour = LEVEL_COLOR.get(level, level)
        logger.warning(
            f"{colour} anomaly: {alert['src_ip']}:{alert['src_port']} → {alert['dst_ip']}:{alert['dst_port']} "
            f"score={alert['score']:.3f}"
        )
    if alerts:
        _write_alert_csv(alerts, csv_path)


def detect_from_csv(
    csv_path: str,
    model: Any,
    scaler: Any,
    red_thr: float,
    yellow_thr: float,
    logger: Any,
    alerts_csv: str,
) -> None:
    """Run detection on a CSV of flows (with columns matching ``flows_to_dataframe``).

    This function does not attempt to aggregate; it expects per‑flow rows.
    """
    df = pd.read_csv(csv_path)
    if df.empty:
        logger.info(f"No flows in CSV {csv_path}")
        return
    _process_dataframe(df, model, scaler, red_thr, yellow_thr, logger, alerts_csv)


def detect_from_pcap(
    pcap_path: str,
    cfg: Dict[str, Any],
    model: Any,
    scaler: Any,
    red_thr: float,
    yellow_thr: float,
    logger: Any,
    alerts_csv: str,
) -> None:
    """Aggregate flows from a PCAP and run detection.

    The PCAP is read sequentially using PyShark.  Once all packets
    within a time window are consumed, the flows for that window are
    scored and logged.  This streaming operation limits memory usage
    on large PCAPs.
    """
    if pyshark is None:
        raise RuntimeError("pyshark is not installed – cannot process PCAPs")
    cap = pyshark.FileCapture(
        pcap_path,
        only_summaries=False,
        keep_packets=False,
        decode_as={"tcp.port==80": "http"},
    )
    window = cfg["window_seconds"]
    feature_set = cfg.get("feature_set", "extended")
    flows: Dict[Tuple[int, Tuple[Any, Any, str]], Dict[str, Any]] = {}
    current_win: Optional[int] = None
    base_ts: Optional[float] = None
    try:
        for pkt in cap:
            try:
                ts = float(pkt.frame_info.time_epoch)
            except Exception:
                continue
            if base_ts is None:
                base_ts = ts
            win_idx = int((ts - base_ts) // window)
            # When the window index increases, flush previous windows
            if current_win is not None and win_idx > current_win:
                # Extract flows for all completed windows and process
                done_flows = {
                    k: v
                    for k, v in flows.items()
                    if k[0] < win_idx
                }
                if done_flows:
                    df = flows_to_dataframe(done_flows, feature_set)
                    _process_dataframe(df, model, scaler, red_thr, yellow_thr, logger, alerts_csv)
                    # Remove processed windows
                    for k in list(done_flows.keys()):
                        flows.pop(k, None)
            current_win = win_idx
            # Aggregate packet
            f = aggregate_packets_to_flows([pkt], window_seconds=window, base_ts=base_ts)
            # Merge into flows dictionary
            for k, st in f.items():
                # Merge sizes and stats
                if k in flows:
                    existing = flows[k]
                    existing["packets"] += st["packets"]
                    existing["bytes"] += st["bytes"]
                    existing["sizes"].extend(st["sizes"])
                    existing["tcp_syn"] += st["tcp_syn"]
                    existing["tcp_fin"] += st["tcp_fin"]
                    existing["tcp_rst"] += st["tcp_rst"]
                    # Update timestamps and IATs
                    prev_ts = existing.get("last_ts")
                    new_first = min(existing["first_ts"], st["first_ts"])
                    new_last = max(existing["last_ts"], st["last_ts"])
                    existing["first_ts"] = new_first
                    existing["last_ts"] = new_last
                    # Append IATs; aggregator already computed relative iat for this flow
                    existing["iat"].extend(st["iat"])
                else:
                    flows[k] = st
    finally:
        cap.close()
    # Flush any remaining flows
    if flows:
        df = flows_to_dataframe(flows, feature_set)
        _process_dataframe(df, model, scaler, red_thr, yellow_thr, logger, alerts_csv)


def detect_live(
    cfg: Dict[str, Any],
    model: Any,
    scaler: Any,
    red_thr: float,
    yellow_thr: float,
    logger: Any,
    alerts_csv: str,
) -> None:
    """Run live detection on the configured interface using PyShark.

    A long‑running loop captures packets, aggregates flows in real time
    and scores them when the window elapses.  Alerts are logged as they
    occur.  The function blocks indefinitely until interrupted.
    """
    if pyshark is None:
        raise RuntimeError("pyshark is not installed – cannot capture live packets")
    interface = cfg.get("iface", "eth0")
    bpf_filter = cfg.get("bpf_filter", "tcp or udp")
    window = cfg["window_seconds"]
    feature_set = cfg.get("feature_set", "extended")
    cap = pyshark.LiveCapture(interface=interface, bpf_filter=bpf_filter)
    logger.info(f"Starting live capture on {interface} with window {window}s")
    flows: Dict[Tuple[int, Tuple[Any, Any, str]], Dict[str, Any]] = {}
    base_ts: Optional[float] = None
    current_win: Optional[int] = None
    try:
        for pkt in cap.sniff_continuously():
            try:
                ts = float(pkt.frame_info.time_epoch)
            except Exception:
                continue
            if base_ts is None:
                base_ts = ts
            win_idx = int((ts - base_ts) // window)
            if current_win is not None and win_idx > current_win:
                done_flows = {k: v for k, v in flows.items() if k[0] < win_idx}
                if done_flows:
                    df = flows_to_dataframe(done_flows, feature_set)
                    _process_dataframe(df, model, scaler, red_thr, yellow_thr, logger, alerts_csv)
                    for k in list(done_flows.keys()):
                        flows.pop(k, None)
            current_win = win_idx
            # Aggregate this single packet into flows
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
                    # update timestamps & iat
                    existing["iat"].extend(st["iat"])
                    existing["first_ts"] = min(existing["first_ts"], st["first_ts"])
                    existing["last_ts"] = max(existing["last_ts"], st["last_ts"])
                else:
                    flows[k] = st
    except KeyboardInterrupt:
        logger.info("Live detection interrupted by user")
    finally:
        cap.close()
        # Flush remaining flows
        if flows:
            df = flows_to_dataframe(flows, feature_set)
            _process_dataframe(df, model, scaler, red_thr, yellow_thr, logger, alerts_csv)


def main() -> None:
    """Entry point for the ids-iforest-detect console script.

    Use ``--pcap`` or ``--csv`` to process files offline.  With no
    file arguments, live capture is used.  A config file is required
    and defaults to ``config/config.yml`` if not specified.
    """
    ap = argparse.ArgumentParser(description="Detect anomalies using a trained Isolation Forest model")
    ap.add_argument("--config", default="config/config.yml", help="Path to configuration YAML file")
    ap.add_argument("--pcap", help="Process flows from the specified PCAP file instead of live capture")
    ap.add_argument("--csv", help="Process flows from the specified CSV file instead of live capture")
    ap.add_argument("--model", help="Explicit model filename to load (overrides latest)")
    ap.add_argument(
        "--alerts-csv",
        default=None,
        help="Path to alerts CSV; defaults to <logs_dir>/alerts.csv from config",
    )
    args = ap.parse_args()
    cfg = load_config(args.config)
    logger = get_logger("detect", cfg["logs_dir"], "detect.log")
    model, scaler, _ = load_model(cfg["model_dir"], explicit_file=args.model)
    red_thr, yellow_thr = load_thresholds(cfg["model_dir"])
    alerts_csv = args.alerts_csv or os.path.join(cfg["logs_dir"], "alerts.csv")
    # Determine mode
    if args.csv:
        detect_from_csv(args.csv, model, scaler, red_thr, yellow_thr, logger, alerts_csv)
    elif args.pcap:
        detect_from_pcap(args.pcap, cfg, model, scaler, red_thr, yellow_thr, logger, alerts_csv)
    else:
        detect_live(cfg, model, scaler, red_thr, yellow_thr, logger, alerts_csv)


if __name__ == "__main__":  # pragma: no cover
    main()