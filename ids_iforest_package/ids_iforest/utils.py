"""Utility functions for the ids_iforest package.

This module contains helpers for loading configuration files, managing
logging, computing the canonical 5‑tuple for network flows, aggregating
packets into flows, converting flows into feature DataFrames, and
handling model persistence.  It is largely based on the original
``ids.utils`` module but updated to use relative imports and with
improved documentation.
"""

from __future__ import annotations

import os
import re
import json
import yaml
import glob
import ipaddress
import logging
import subprocess
from dataclasses import dataclass
from typing import Dict, Any, Tuple, Optional, Iterable, List

import numpy as np
import pandas as pd

try:
    from colorama import Fore, Style, init as colorama_init  # type: ignore
except Exception:
    # Graceful degradation when colorama is not available.
    class _Dummy:
        def __getattr__(self, name: str) -> str:
            return ""
    Fore = Style = _Dummy()  # type: ignore[assignment]
    def colorama_init(autoreset: bool = True) -> None:
        return None

import joblib

__all__ = [
    "load_config",
    "ensure_dirs",
    "get_logger",
    "get_git_hash",
    "save_model",
    "load_model",
    "load_thresholds",
    "aggregate_packets_to_flows",
    "flows_to_dataframe",
    "level_for_score",
    "LEVEL_COLOR",
]


def load_config(path: str) -> Dict[str, Any]:
    """Load a YAML configuration file and resolve relative paths.

    The configuration may specify relative paths for ``model_dir`` and
    ``logs_dir``.  Those are resolved relative to the directory
    containing the configuration file.  Default values are applied for
    any missing keys.

    Parameters
    ----------
    path: str
        Path to the YAML configuration file.

    Returns
    -------
    Dict[str, Any]
        A dictionary of configuration values.
    """
    with open(path, "r", encoding="utf-8") as f:
        cfg: Dict[str, Any] = yaml.safe_load(f) or {}
    # Defaults
    cfg.setdefault("window_seconds", 10)
    cfg.setdefault("bpf_filter", "tcp or udp")
    cfg.setdefault("feature_set", "extended")
    cfg.setdefault("contamination", 0.02)
    cfg.setdefault("model_dir", "./models")
    cfg.setdefault("logs_dir", "./logs")
    cfg.setdefault("iface", "eth0")
    # Resolve relative paths w.r.t the config file
    base = os.path.dirname(os.path.abspath(path))
    for key in ("model_dir", "logs_dir"):
        val = cfg.get(key)
        if isinstance(val, str) and not os.path.isabs(val):
            cfg[key] = os.path.abspath(os.path.join(base, val))
    return cfg


def ensure_dirs(*paths: str) -> None:
    """Create any missing directories in ``paths``.

    ``os.makedirs`` with ``exist_ok=True`` ensures idempotency.
    """
    for p in paths:
        os.makedirs(p, exist_ok=True)


def get_logger(name: str, logs_dir: str, base_filename: str) -> logging.Logger:
    """Return a configured logger that writes both to file and stdout.

    This helper ensures that a single logger is configured only once per
    name.  A new file handler and stream handler are attached on the
    first call; subsequent calls reuse the same logger.

    Parameters
    ----------
    name: str
        The logger name.
    logs_dir: str
        Directory where log files are written.
    base_filename: str
        Base filename for the log file; the suffix ``.log`` is not
        automatically added, so include it explicitly.

    Returns
    -------
    logging.Logger
        A configured logger.
    """
    ensure_dirs(logs_dir)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        log_path = os.path.join(logs_dir, f"{base_filename}")
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        sh = logging.StreamHandler()
        sh.setFormatter(fmt)
        logger.addHandler(sh)
    return logger


def get_git_hash(short: bool = True) -> str:
    """Return the current Git commit hash, or ``unknown`` on failure.

    In CI/CD environments the hash may be supplied via the
    ``CI_COMMIT_SHA`` environment variable.

    Parameters
    ----------
    short: bool, optional
        If true (the default), return the first 8 characters of the hash.
    """
    env_sha = os.getenv("CI_COMMIT_SHA")
    if env_sha:
        return env_sha[:8] if short else env_sha
    try:
        sha = (
            subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL)
            .decode()
            .strip()
        )
        return sha[:8] if short else sha
    except Exception:
        return "unknown"


def save_model(model: Any, scaler: Any, model_dir: str) -> Tuple[str, str]:
    """Persist a trained model and scaler using joblib.

    The model is saved to a timestamped filename and a copy is made to
    ``ids_iforest_latest.joblib`` for easy loading.  The model directory
    is created if necessary.

    Returns
    -------
    Tuple[str, str]
        A tuple of (model_path, latest_path).
    """
    ensure_dirs(model_dir)
    git_hash = get_git_hash()
    model_path = os.path.join(model_dir, f"ids_iforest_{git_hash}.joblib")
    payload = {"model": model, "scaler": scaler}
    joblib.dump(payload, model_path)
    latest_path = os.path.join(model_dir, "ids_iforest_latest.joblib")
    # Try to replace any existing latest copy
    try:
        if os.path.exists(latest_path):
            os.remove(latest_path)
    except Exception:
        pass
    try:
        import shutil
        shutil.copyfile(model_path, latest_path)
    except Exception:
        pass
    return model_path, latest_path


def load_model(model_dir: str, explicit_file: Optional[str] = None) -> Tuple[Any, Any, str]:
    """Load a model and scaler from disk.

    If ``explicit_file`` is provided, load that file; otherwise load the
    ``ids_iforest_latest.joblib`` or, failing that, the most recent
    ``ids_iforest_*.joblib`` in the directory.  Raises
    ``FileNotFoundError`` if no model is found.

    Returns
    -------
    Tuple[Any, Any, str]
        A tuple of (model, scaler, path).
    """
    path: Optional[str] = None
    if explicit_file:
        path = explicit_file if os.path.isabs(explicit_file) else os.path.join(model_dir, explicit_file)
    else:
        latest = os.path.join(model_dir, "ids_iforest_latest.joblib")
        if os.path.exists(latest):
            path = latest
        else:
            cands = sorted(glob.glob(os.path.join(model_dir, "ids_iforest_*.joblib")), key=os.path.getmtime)
            path = cands[-1] if cands else None
    if not path or not os.path.exists(path):
        raise FileNotFoundError(
            f"No model found in {model_dir}.  Train a model first with ids-iforest-train."
        )
    payload = joblib.load(path)
    return payload["model"], payload["scaler"], path


def load_thresholds(model_dir: str) -> Tuple[float, float]:
    """Load alert thresholds from ``thresholds.json`` in ``model_dir``.

    If the file is missing or invalid, return default values of
    (–0.25, 0.0).
    """
    path = os.path.join(model_dir, "thresholds.json")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        red = float(data.get("red_threshold", -0.25))
        yellow = float(data.get("yellow_threshold", 0.0))
        return red, yellow
    except Exception:
        return -0.25, 0.0


@dataclass(frozen=True)
class Endpoint:
    """Representation of a network endpoint (IP address and port)."""
    ip: str
    port: int


def _endpoint_order(ep: Endpoint) -> Tuple[int, bytes, int]:
    """Return a key used to order endpoints (IPv4 before IPv6, lexicographically)."""
    ip_obj = ipaddress.ip_address(ep.ip)
    return (ip_obj.version, ip_obj.packed, ep.port)


def canonical_5tuple(src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str) -> Tuple[Endpoint, Endpoint, str]:
    """Return a canonical ordering of the 5‑tuple (IP/port pair and protocol).

    The ordering is stable across IPv4/IPv6 and ensures that the same
    bidirectional flow maps to a unique key regardless of direction.
    """
    a = Endpoint(src_ip, int(src_port))
    b = Endpoint(dst_ip, int(dst_port))
    a1, a2 = (a, b) if _endpoint_order(a) <= _endpoint_order(b) else (b, a)
    return a1, a2, proto.lower()


def packet_to_minimal_fields(pkt: Any) -> Optional[Dict[str, Any]]:
    """Extract minimal fields from a PyShark packet for flow aggregation.

    Returns a dictionary with source/destination IP/port, protocol,
    length, timestamp and TCP flag counts.  Returns ``None`` if the
    packet is not TCP or UDP or lacks sufficient information.
    """
    try:
        proto = getattr(pkt, "transport_layer", None)
        if proto is None:
            return None
        proto = proto.lower()
        if proto not in ("tcp", "udp"):
            return None
        # IP addresses (IPv4 or IPv6)
        if hasattr(pkt, "ip"):
            src_ip = pkt.ip.src
            dst_ip = pkt.ip.dst
        elif hasattr(pkt, "ipv6"):
            src_ip = pkt.ipv6.src
            dst_ip = pkt.ipv6.dst
        else:
            return None
        layer = getattr(pkt, proto)
        src_port = int(layer.srcport)
        dst_port = int(layer.dstport)
        length = int(getattr(pkt, "length", getattr(pkt.frame_info, "len", 0)))
        ts = float(getattr(pkt.frame_info, "time_epoch"))
        syn = fin = rst = 0
        if proto == "tcp":
            tcp = pkt.tcp
            syn = int(getattr(tcp, "flags_syn", 0) or 0)
            fin = int(getattr(tcp, "flags_fin", 0) or 0)
            rst = int(getattr(tcp, "flags_reset", getattr(tcp, "flags_rst", 0)) or 0)
        return {
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": proto,
            "length": length,
            "ts": ts,
            "tcp_syn": syn,
            "tcp_fin": fin,
            "tcp_rst": rst,
        }
    except Exception:
        return None


def aggregate_packets_to_flows(
    packets: Iterable[Any],
    window_seconds: int,
    base_ts: Optional[float] = None,
) -> Dict[Tuple[int, Tuple[Endpoint, Endpoint, str]], Dict[str, Any]]:
    """Aggregate packets into bidirectional flows keyed by time window and 5‑tuple.

    Parameters
    ----------
    packets: Iterable[Any]
        An iterable of PyShark packets or objects exposing similar attributes.
    window_seconds: int
        Duration of a window in seconds.  Packets falling into the same
        time window (relative to the first packet timestamp) are grouped.
    base_ts: float, optional
        Optional base timestamp.  If provided, window indices are
        computed relative to this timestamp instead of the first packet.

    Returns
    -------
    Dict[Tuple[int, Tuple[Endpoint, Endpoint, str]], Dict[str, Any]]
        A mapping from (window index, 5‑tuple key) to accumulated statistics.
    """
    flows: Dict[Tuple[int, Tuple[Endpoint, Endpoint, str]], Dict[str, Any]] = {}
    first_ts: Optional[float] = base_ts
    last_seen_per_flow: Dict[Tuple[int, Tuple[Endpoint, Endpoint, str]], float] = {}
    for pkt in packets:
        f = packet_to_minimal_fields(pkt)
        if not f:
            continue
        ts = f["ts"]
        if first_ts is None:
            first_ts = ts
        # Compute window index
        win_idx = int((ts - first_ts) // window_seconds)
        key = canonical_5tuple(f["src_ip"], f["src_port"], f["dst_ip"], f["dst_port"], f["protocol"])
        fk = (win_idx, key)
        st = flows.get(fk)
        if st is None:
            st = {
                "a": key[0],
                "b": key[1],
                "protocol": key[2],
                "packets": 0,
                "bytes": 0,
                "sizes": [],
                "first_ts": ts,
                "last_ts": ts,
                "iat": [],
                "tcp_syn": 0,
                "tcp_fin": 0,
                "tcp_rst": 0,
            }
            flows[fk] = st
        prev_ts = last_seen_per_flow.get(fk)
        if prev_ts is not None:
            st["iat"].append(max(0.0, ts - prev_ts))
        last_seen_per_flow[fk] = ts
        st["packets"] += 1
        st["bytes"] += int(f["length"])
        st["sizes"].append(int(f["length"]))
        st["last_ts"] = ts
        st["tcp_syn"] += int(f["tcp_syn"]) if f["protocol"] == "tcp" else 0
        st["tcp_fin"] += int(f["tcp_fin"]) if f["protocol"] == "tcp" else 0
        st["tcp_rst"] += int(f["tcp_rst"]) if f["protocol"] == "tcp" else 0
    return flows


def flows_to_dataframe(
    flows: Dict[Tuple[int, Tuple[Endpoint, Endpoint, str]], Dict[str, Any]],
    feature_set: str,
) -> pd.DataFrame:
    """Convert an aggregated flow dictionary into a Pandas DataFrame.

    The DataFrame columns are ordered and stable.  Two feature sets are
    supported: ``minimal`` and ``extended``.  When no flows are
    provided, an empty DataFrame with the appropriate columns is
    returned.
    """
    rows: List[Dict[str, Any]] = []
    for (win_idx, key), st in flows.items():
        duration = max(0.0, st["last_ts"] - st["first_ts"]) if st["packets"] > 1 else (st["last_ts"] - st["first_ts"]) or 0.0
        mean_ps = float(np.mean(st["sizes"])) if st["sizes"] else 0.0
        std_ps = float(np.std(st["sizes"])) if st["sizes"] else 0.0
        iat_mean = float(np.mean(st["iat"])) if st["iat"] else 0.0
        iat_std = float(np.std(st["iat"])) if st["iat"] else 0.0
        pps = (st["packets"] / duration) if duration > 0 else float(st["packets"])
        bpp = (st["bytes"] / st["packets"]) if st["packets"] > 0 else 0.0
        row: Dict[str, Any] = {
            "window": int(win_idx),
            "src_ip": st["a"].ip,
            "dst_ip": st["b"].ip,
            "src_port": st["a"].port,
            "dst_port": st["b"].port,
            "protocol": st["protocol"],
            "bidirectional_packets": int(st["packets"]),
            "bidirectional_bytes": int(st["bytes"]),
            "mean_packet_size": mean_ps,
            "std_packet_size": std_ps,
            "flow_duration": duration,
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
    df = pd.DataFrame(rows)
    minimal_cols = [
        "window", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "bidirectional_packets", "bidirectional_bytes", "mean_packet_size", "std_packet_size", "flow_duration",
    ]
    extended_cols = minimal_cols + [
        "tcp_syn_count", "tcp_fin_count", "tcp_rst_count", "iat_mean", "iat_std", "bytes_per_packet", "packets_per_second",
    ]
    if df.empty:
        return pd.DataFrame(columns=extended_cols if feature_set == "extended" else minimal_cols)
    return df[extended_cols if feature_set == "extended" else minimal_cols]


# Colourised levels for console output.  These constants are used in the
# detection module to colour anomalous flows.  When colourama is not
# available the values degrade gracefully to plain strings.
colorama_init(autoreset=True)
LEVEL_COLOR: Dict[str, str] = {
    "GREEN": Fore.GREEN + "GREEN" + Style.RESET_ALL,
    "YELLOW": Fore.YELLOW + "YELLOW" + Style.RESET_ALL,
    "RED": Fore.RED + "RED" + Style.RESET_ALL,
}


def level_for_score(score: float) -> str:
    """Return an alert level name for a given Isolation Forest score.

    This function is kept for backward compatibility.  Modern
    implementations should instead call ``load_thresholds`` and apply
    thresholds dynamically.
    """
    if score < -0.25:
        return "RED"
    if score < 0:
        return "YELLOW"
    return "GREEN"
