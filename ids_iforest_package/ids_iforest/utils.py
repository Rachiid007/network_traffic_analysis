"""Utility functions for the ids_iforest package (live-only workflow)."""

from __future__ import annotations

import os
import json
import yaml
import glob
import ipaddress
import logging
import subprocess
import sys
from dataclasses import dataclass
from typing import Dict, Any, Tuple, Optional, Iterable, List

import numpy as np
import pandas as pd
import joblib

try:
    from colorama import Fore, Style, init as colorama_init  # type: ignore
except Exception:
    class _Dummy:
        def __getattr__(self, name: str) -> str:
            return ""
    Fore = Style = _Dummy()  # type: ignore[assignment]
    def colorama_init(autoreset: bool = True) -> None:
        return None

__all__ = [
    "load_config",
    "ensure_dirs",
    "get_logger",
    "get_git_hash",
    "save_model",
    "load_model",
    "load_thresholds",
    "canonical_5tuple",
    "LEVEL_COLOR",
]


def load_config(path: str) -> Dict[str, Any]:
    """Load YAML config and resolve paths; allow ENV overrides for Docker."""
    with open(path, "r", encoding="utf-8") as f:
        cfg: Dict[str, Any] = yaml.safe_load(f) or {}

    # Defaults
    cfg.setdefault("window_seconds", 5)
    cfg.setdefault("bpf_filter", "tcp or udp")
    cfg.setdefault("feature_set", "extended")
    cfg.setdefault("model_dir", "./models")
    cfg.setdefault("logs_dir", "./logs")
    cfg.setdefault("iface", "eth0")

    base = os.path.dirname(os.path.abspath(path))

    # ENV overrides (highest precedence)
    env_model = os.getenv("IDS_MODEL_DIR")
    env_logs = os.getenv("IDS_LOGS_DIR")
    env_iface = os.getenv("IFACE") or os.getenv("IDS_IFACE")
    if env_model:
        cfg["model_dir"] = env_model
    if env_logs:
        cfg["logs_dir"] = env_logs
    if env_iface:
        cfg["iface"] = env_iface

    # Resolve relative paths
    for key in ("model_dir", "logs_dir"):
        val = cfg.get(key)
        if isinstance(val, str) and not os.path.isabs(val):
            cfg[key] = os.path.abspath(os.path.join(base, val))

    # Try to ensure directories are usable; fallbacks if needed
    def _writable(target: str) -> bool:
        try:
            os.makedirs(target, exist_ok=True)
            test_file = os.path.join(target, ".writetest")
            with open(test_file, "w", encoding="utf-8") as tf:
                tf.write("ok")
            os.remove(test_file)
            return True
        except Exception:
            return False

    in_container = os.path.exists("/.dockerenv") or os.path.isfile("/proc/1/cgroup")

    for key, default_rel in (("model_dir", "models"), ("logs_dir", "logs")):
        cur = cfg.get(key)
        if not isinstance(cur, str):
            continue
        # model_dir may be read-only but acceptable if it already contains a model
        if key == "model_dir":
            try:
                if os.path.isdir(cur):
                    latest = os.path.join(cur, "ids_iforest_latest.joblib")
                    any_model = bool(
                        os.path.exists(latest)
                        or glob.glob(os.path.join(cur, "ids_iforest_*.joblib"))
                    )
                    if any_model and os.access(cur, os.R_OK):
                        continue
            except Exception:
                pass
        if _writable(cur):
            continue
        candidates: List[str] = []
        if in_container:
            candidates.append(f"/app/{default_rel}")
        candidates.append(os.path.abspath(os.path.join(os.getcwd(), default_rel)))
        home = os.path.expanduser("~")
        candidates.append(os.path.join(home, ".ids_iforest", default_rel))
        for cand in candidates:
            if _writable(cand):
                fb = cfg.setdefault("_path_fallbacks", {})  # type: ignore[assignment]
                fb[key] = {"original": cur, "chosen": cand}
                print(f"[ids-iforest] WARNING: {key} '{cur}' not writable; using '{cand}'")
                cfg[key] = cand
                break

    return cfg


def ensure_dirs(*paths: str) -> None:
    for p in paths:
        os.makedirs(p, exist_ok=True)


def get_logger(name: str, logs_dir: str, base_filename: str) -> logging.Logger:
    """Logger that writes to file and stdout (Docker-friendly)."""
    ensure_dirs(logs_dir)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        log_path = os.path.join(logs_dir, base_filename)
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
        fh.setFormatter(fmt)
        logger.addHandler(fh)
        sh = logging.StreamHandler(sys.stdout)
        sh.setFormatter(fmt)
        logger.addHandler(sh)
    return logger


def get_git_hash(short: bool = True) -> str:
    env_sha = os.getenv("CI_COMMIT_SHA")
    if env_sha:
        return env_sha[:8] if short else env_sha
    try:
        sha = subprocess.check_output(["git", "rev-parse", "HEAD"], stderr=subprocess.DEVNULL).decode().strip()
        return sha[:8] if short else sha
    except Exception:
        return "unknown"


def save_model(model: Any, scaler: Any, model_dir: str) -> Tuple[str, str]:
    ensure_dirs(model_dir)
    git_hash = get_git_hash()
    model_path = os.path.join(model_dir, f"ids_iforest_{git_hash}.joblib")
    joblib.dump({"model": model, "scaler": scaler}, model_path)
    latest_path = os.path.join(model_dir, "ids_iforest_latest.joblib")
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
            f"No model found in {model_dir}. Train first with ids-iforest-train."
        )
    payload = joblib.load(path)
    return payload["model"], payload["scaler"], path


def load_thresholds(model_dir: str) -> Tuple[float, float]:
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
    ip: str
    port: int


def _endpoint_order(ep: Endpoint) -> Tuple[int, bytes, int]:
    ip_obj = ipaddress.ip_address(ep.ip)
    return (ip_obj.version, ip_obj.packed, ep.port)


def canonical_5tuple(
    src_ip: str, src_port: int, dst_ip: str, dst_port: int, proto: str
) -> Tuple[Endpoint, Endpoint, str]:
    a = Endpoint(src_ip, int(src_port))
    b = Endpoint(dst_ip, int(dst_port))
    a1, a2 = (a, b) if _endpoint_order(a) <= _endpoint_order(b) else (b, a)
    return a1, a2, proto.lower()


# Colourised levels (console). Gracefully degrade when colorama is absent.
colorama_init(autoreset=True)
LEVEL_COLOR: Dict[str, str] = {
    "GREEN": Fore.GREEN + "GREEN" + Style.RESET_ALL,
    "YELLOW": Fore.YELLOW + "YELLOW" + Style.RESET_ALL,
    "RED":   Fore.RED    + "RED"    + Style.RESET_ALL,
}
