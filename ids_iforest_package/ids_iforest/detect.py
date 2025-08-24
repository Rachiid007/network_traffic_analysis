"""Live anomaly detection using tshark (Docker/Windows friendly).

- Capt    all_numeric_cols = numeric_cols + extended
    X = scaler.transform(df[all_numeric_cols].fillna(0.0).astype(float).values)
    scores = model.decision_function(X)
    now_str = _dt.datetime.utcnow().isoformat()s packets via tshark in "fields" mode (no pyshark).
- Aggregates packets into time-windowed flows.
- Scores flows using a trained Isolation Forest + scaler.
- Writes anomalies to alerts.jsonl (Grafana/Promtail) and alerts.csv.
"""

from __future__ import annotations

import argparse
import csv
import datetime as _dt
import os
import shutil
import statistics as stats
import subprocess
import threading
import time
from typing import Optional, Tuple, Dict, Any, Iterable, List

import pandas as pd  # type: ignore

from .utils import (
    load_config,
    get_logger,
    load_model,
    load_thresholds,
)

__all__ = ["main"]


# ----------------------------
# Scoring & alert persistence
# ----------------------------
def _score_flows(
    model: Any,
    scaler: Any,
    df: pd.DataFrame,
    red_thr: float,
    yellow_thr: float,
) -> Iterable[Tuple[str, Dict[str, Any]]]:
    """Score each flow and yield (level, alert_dict) for anomalies."""
    if df.empty:
        return []  # type: ignore

    numeric_cols = [
        "bidirectional_packets",
        "bidirectional_bytes",
        "mean_packet_size",
        "std_packet_size",
        "flow_duration",
    ]
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

    # Use timezone-aware datetime objects for UTC time (fixing deprecation warning)
    try:
        # Python 3.11+ has UTC constant
        now_str = _dt.datetime.now(_dt.UTC).isoformat()
    except AttributeError:
        # Fallback for older Python versions
        now_str = _dt.datetime.now(_dt.timezone.utc).isoformat()

    for idx, s in enumerate(scores):
        score_f = float(s)
        if score_f < yellow_thr:
            level = "RED" if score_f < red_thr else "YELLOW"
            row = df.iloc[idx]
            yield level, {
                "timestamp": now_str,
                "src_ip": row["src_ip"],
                "dst_ip": row["dst_ip"],
                "src_port": int(row["src_port"]),
                "dst_port": int(row["dst_port"]),
                "protocol": row["protocol"],
                "score": score_f,
                "level": level,
            }


def _write_alert_csv(
    alerts: Iterable[Tuple[str, Dict[str, Any]]], csv_path: str
) -> None:
    """Append alert rows to the CSV file (header on first write)."""
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
    """Score flows in `df` and log any anomalies."""
    # Score all flows to compute distribution
    if not df.empty:
        numeric_cols = [
            "bidirectional_packets",
            "bidirectional_bytes",
            "mean_packet_size",
            "std_packet_size",
            "flow_duration",
            "tcp_syn_count",
            "tcp_fin_count",
            "tcp_rst_count",
            "iat_mean",
            "iat_std",
            "bytes_per_packet",
            "packets_per_second",
        ]
        X = scaler.transform(df[numeric_cols].fillna(0.0).astype(float).values)
        scores = model.decision_function(X)
        min_s, max_s = float(min(scores)), float(max(scores))
        mean_s = float(sum(scores) / len(scores))
        # Optionally compute percentiles with numpy or statistics.quantiles
        logger.info(
            f"Score stats: count={len(scores)} min={min_s:.4f} "
            f"mean={mean_s:.4f} max={max_s:.4f}"
        )

    alerts = list(_score_flows(model, scaler, df, red_thr, yellow_thr))
    logger.info(f"Scored {len(df)} flows, produced {len(alerts)} alerts")

    json_path = os.path.join(os.path.dirname(csv_path), "alerts.jsonl")
    if alerts:
        from .logging_utils import append_json_alert  # local import to avoid cycles
        for level, alert in alerts:
            append_json_alert(json_path, **alert)
            if level == "RED":
                logger.error(
                    f"ANOMALY RED {alert['src_ip']}:{alert['src_port']} -> "
                    f"{alert['dst_ip']}:{alert['dst_port']} {alert['protocol'].upper()} "
                    f"score={alert['score']:.4f}"
                )
            else:
                logger.warning(
                    f"Anomaly YELLOW {alert['src_ip']}:{alert['src_port']} -> "
                    f"{alert['dst_ip']}:{alert['dst_port']} {alert['protocol'].upper()} "
                    f"score={alert['score']:.4f}"
                )
        _write_alert_csv(alerts, csv_path)
        logger.info(f"Wrote {len(alerts)} alert(s) to {csv_path} and {json_path}")


# ------------------------------------------
# Live detection via tshark (robust choice)
# ------------------------------------------
def _flows_to_df(
    flows: Dict[Tuple[int, str, str, int, int, str], Dict[str, Any]],
    feature_set: str,
) -> pd.DataFrame:
    """Build a pandas DF with the columns the model expects."""
    rows: List[Dict[str, Any]] = []
    for st in flows.values():
        packets = int(st["packets"])
        bytes_ = int(st["bytes"])
        sizes = st["sizes"]
        dur = max(1e-6, float(st["last_ts"] - st["first_ts"]))
        mean_sz = float(sum(sizes) / packets) if packets > 0 else 0.0
        std_sz = float((stats.pstdev(sizes) if len(sizes) > 1 else 0.0)) if packets > 0 else 0.0
        iat = st["iat"]
        iat_mean = float(sum(iat) / len(iat)) if iat else 0.0
        iat_std = float(stats.pstdev(iat) if len(iat) > 1 else 0.0) if iat else 0.0
        bpp = float(bytes_ / packets) if packets > 0 else 0.0
        pps = float(packets / dur) if dur > 0 else float(packets)

        row = {
            "src_ip": st["src_ip"],
            "dst_ip": st["dst_ip"],
            "src_port": st["src_port"],
            "dst_port": st["dst_port"],
            "protocol": st["protocol"],
            "bidirectional_packets": packets,
            "bidirectional_bytes": bytes_,
            "mean_packet_size": mean_sz,
            "std_packet_size": std_sz,
            "flow_duration": dur,
        }
        if feature_set == "extended":
            row.update({
                "tcp_syn_count": int(st["tcp_syn"]),
                "tcp_fin_count": int(st["tcp_fin"]),
                "tcp_rst_count": int(st["tcp_rst"]),
                "iat_mean": iat_mean,
                "iat_std": iat_std,
                "bytes_per_packet": bpp,
                "packets_per_second": pps,
            })
        rows.append(row)
    return pd.DataFrame(rows)


def _flag_to_int(v: str) -> int:
    """Coerce tshark boolean-like outputs ('True'/'False', '1'/'0', '') to 0/1."""
    if v is None:
        return 0
    s = str(v).strip().lower()
    if s in ("1", "true", "t", "yes", "y"):
        return 1
    if s in ("0", "false", "f", "no", "n", ""):
        return 0
    # Some tshark versions might emit numeric or hex-y values in odd cases;
    # treat any nonzero integer as True.
    try:
        return 1 if int(s) != 0 else 0
    except Exception:
        return 0


def detect_live(
    cfg: Dict[str, Any],
    model: Any,
    scaler: Any,
    red_thr: float,
    yellow_thr: float,
    logger: Any,
    alerts_csv: str,
) -> None:
    """Run live detection using tshark streaming."""
    # Interface selection: ENV takes precedence (Windows/Docker convenience)
    interface = os.getenv("IFACE") or os.getenv("IDS_IFACE") or cfg.get("iface", "eth0")
    bpf_filter = cfg.get("bpf_filter", "tcp or udp")
    window = int(cfg.get("window_seconds", 10))
    feature_set = cfg.get("feature_set", "extended")

    tshark_path = shutil.which("tshark")
    if not tshark_path:
        raise RuntimeError("tshark not found in PATH; cannot do live capture")

    # Ensure alerts.jsonl exists (Promtail tail target)
    json_path = os.path.join(os.path.dirname(alerts_csv), "alerts.jsonl")
    os.makedirs(os.path.dirname(json_path), exist_ok=True)
    open(json_path, "a").close()

    cmd = [
        tshark_path, "-n",
        "-i", interface,
        "-f", bpf_filter,
        "-l",
        "-T", "fields",
        "-E", "separator=,",
        "-E", "header=n",
        "-E", "quote=n",
        "-e", "frame.time_epoch",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "tcp.srcport", "-e", "tcp.dstport",
        "-e", "udp.srcport", "-e", "udp.dstport",
        "-e", "frame.len",
        "-e", "tcp.flags.syn", "-e", "tcp.flags.fin", "-e", "tcp.flags.reset",
    ]

    logger.info(
        f"Starting live capture on '{interface}' window={window}s filter=\"{bpf_filter}\"; "
        f"tshark cmd={' '.join(cmd)}"
    )

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,  # show tshark errors in our logs
        text=True,
        bufsize=1,
        universal_newlines=True,
    )

    flows: Dict[Tuple[int, str, str, int, int, str], Dict[str, Any]] = {}
    base_ts: Optional[float] = None
    current_win: Optional[int] = None
    last_pkt_ts: Optional[float] = None
    lock = threading.Lock()
    stop = threading.Event()

    # ingest stats
    lines_total = 0
    lines_parsed = 0
    lines_skipped = 0

    def _flush(older_only: bool = True) -> None:
        """Flush buffered flows; if older_only, flush windows < current."""
        nonlocal flows, current_win
        with lock:
            if not flows:
                return
            if older_only and current_win is not None:
                done = {k: v for k, v in flows.items() if k[0] < current_win}
            else:
                done = dict(flows)
            if not done:
                return
            for k in list(done.keys()):
                flows.pop(k, None)
        df = _flows_to_df(done, feature_set)
        _process_dataframe(df, model, scaler, red_thr, yellow_thr, logger, alerts_csv)

    def _flusher_loop() -> None:
        idle_timeout = max(2, window)      # flush everything if idle ≥ window
        tick = max(1, window // 2)         # run 2x per window
        nonlocal lines_total, lines_parsed, lines_skipped
        last_log = time.time()
        while not stop.is_set():
            time.sleep(tick)
            with lock:
                has_flows = bool(flows)
                lp = last_pkt_ts
            if has_flows:
                _flush(older_only=True)
            now = time.time()
            if lp and (now - lp) >= idle_timeout:
                _flush(older_only=False)
            # periodic ingest stats
            if now - last_log >= max(5, window):
                logger.info(
                    f"Ingest stats: total_lines={lines_total} parsed={lines_parsed} "
                    f"skipped={lines_skipped} active_flows={len(flows)}"
                )
                last_log = now

    flusher = threading.Thread(target=_flusher_loop, daemon=True)
    flusher.start()

    try:
        assert proc.stdout is not None
        for raw_line in proc.stdout:
            line = raw_line.strip()
            if not line:
                continue
            # TShark status/errors (keep visible)
            if line.startswith("Capturing on"):
                logger.info(line)
                continue
            if line.startswith("tshark:"):
                logger.error(line)
                continue

            lines_total += 1
            parts = line.split(",")
            if len(parts) < 11:
                lines_skipped += 1
                continue

            try:
                ts = float(parts[0]) if parts[0] else None
                ip_src = parts[1] or None
                ip_dst = parts[2] or None
                tcp_sp = parts[3]
                tcp_dp = parts[4]
                udp_sp = parts[5]
                udp_dp = parts[6]
                frame_len = int(parts[7] or 0)
                syn = _flag_to_int(parts[8])
                fin = _flag_to_int(parts[9])
                rst = _flag_to_int(parts[10])
            except Exception:
                lines_skipped += 1
                continue

            if ts is None or ip_src is None or ip_dst is None:
                lines_skipped += 1
                continue

            # Determine protocol & ports
            proto = None
            sp = dp = 0
            if tcp_sp or tcp_dp:
                proto = "tcp"
                try:
                    sp = int(tcp_sp or 0)
                    dp = int(tcp_dp or 0)
                except Exception:
                    lines_skipped += 1
                    continue
            elif udp_sp or udp_dp:
                proto = "udp"
                try:
                    sp = int(udp_sp or 0)
                    dp = int(udp_dp or 0)
                except Exception:
                    lines_skipped += 1
                    continue
            else:
                lines_skipped += 1
                continue  # non-TCP/UDP (shouldn't happen due to BPF)

            with lock:
                if base_ts is None:
                    base_ts = ts
                win_idx = int((ts - base_ts) // window)
                current_win = win_idx
                last_pkt_ts = ts

                key = (win_idx, ip_src, ip_dst, sp, dp, proto)
                st = flows.get(key)
                if st is None:
                    st = flows[key] = {
                        "src_ip": ip_src, "dst_ip": ip_dst,
                        "src_port": sp, "dst_port": dp,
                        "protocol": proto,
                        "packets": 0, "bytes": 0, "sizes": [],
                        "tcp_syn": 0, "tcp_fin": 0, "tcp_rst": 0,
                        "iat": [], "first_ts": ts, "last_ts": ts, "_last_ts": None,
                    }
                st["packets"] += 1
                st["bytes"] += frame_len
                st["sizes"].append(frame_len)
                if proto == "tcp":
                    st["tcp_syn"] += 1 if syn else 0
                    st["tcp_fin"] += 1 if fin else 0
                    st["tcp_rst"] += 1 if rst else 0
                if st["_last_ts"] is not None:
                    st["iat"].append(max(0.0, ts - float(st["_last_ts"])))
                st["_last_ts"] = ts
                st["last_ts"] = ts
                lines_parsed += 1
    except KeyboardInterrupt:
        logger.info("Live detection interrupted by user")
    finally:
        try:
            stop.set()
            flusher.join(timeout=1.0)
        except Exception:
            pass
        try:
            proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=1.0)
        except Exception:
            pass
        _flush(older_only=False)  # final flush


# -------------------------
# CLI entry point
# -------------------------
def main() -> None:
    ap = argparse.ArgumentParser(
        description="Detect anomalies using a trained Isolation Forest model (live only)"
    )
    ap.add_argument("--config", default="config/config.yml", help="Path to configuration YAML file")
    ap.add_argument("--model", help="Explicit model filename to load (overrides latest)")
    ap.add_argument("--alerts-csv", default=None,
                    help="Path to alerts CSV; defaults to <logs_dir>/alerts.csv from config")
    args = ap.parse_args()

    cfg = load_config(args.config)
    logger = get_logger("detect", cfg["logs_dir"], "detect.log")
    model, scaler, _ = load_model(cfg["model_dir"], explicit_file=args.model)
    red_thr, yellow_thr = load_thresholds(cfg["model_dir"])

    # Optional env overrides for demo sensitivity
    if os.getenv("IDS_RED_THRESHOLD"):
        try:
            red_thr = float(os.getenv("IDS_RED_THRESHOLD", "").strip())
            logger.info(f"Overriding red_threshold via env: {red_thr}")
        except Exception:
            pass
    if os.getenv("IDS_YELLOW_THRESHOLD"):
        try:
            yellow_thr = float(os.getenv("IDS_YELLOW_THRESHOLD", "").strip())
            logger.info(f"Overriding yellow_threshold via env: {yellow_thr}")
        except Exception:
            pass

    alerts_csv = args.alerts_csv or os.path.join(cfg["logs_dir"], "alerts.csv")
    os.makedirs(os.path.dirname(alerts_csv), exist_ok=True)
    open(os.path.join(os.path.dirname(alerts_csv), "alerts.jsonl"), "a").close()

    detect_live(cfg, model, scaler, red_thr, yellow_thr, logger, alerts_csv)


if __name__ == "__main__":
    main()
