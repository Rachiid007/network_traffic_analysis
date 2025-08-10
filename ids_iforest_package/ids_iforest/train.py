"""Train an Isolation Forest model on a flows CSV dataset.

This module defines a ``train`` function that takes a CSV file of
network flow features, a configuration file and an output directory.
It normalises the numeric features with a ``StandardScaler`` and
trains an ``IsolationForest`` model.  If labels are present, the
contamination parameter is calibrated by performing a simple grid
search over a handful of candidate contamination rates.  Synthetic
outliers can optionally be injected into the training data to help the
model learn to assign lower scores to extreme points.  The trained
model and scaler are persisted via joblib, and alert thresholds are
saved to ``thresholds.json`` in the output directory.

This module exposes a ``main`` function so it can be used as a console
script (see ``pyproject.toml``) via ``ids-iforest-train``.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import List, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

from .utils import load_config, get_logger, ensure_dirs, save_model, get_git_hash

__all__ = ["train", "main"]


MINIMAL_COLS: List[str] = [
    "window", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "bidirectional_packets", "bidirectional_bytes", "mean_packet_size",
    "std_packet_size", "flow_duration",
]
EXTENDED_COLS: List[str] = MINIMAL_COLS + [
    "tcp_syn_count", "tcp_fin_count", "tcp_rst_count",
    "iat_mean", "iat_std", "bytes_per_packet", "packets_per_second",
]


def _select_numeric(df: pd.DataFrame, feature_set: str) -> pd.DataFrame:
    """Return only the numeric columns relevant for Isolation Forest training."""
    cols = [
        "bidirectional_packets", "bidirectional_bytes", "mean_packet_size",
        "std_packet_size", "flow_duration",
    ]
    if feature_set == "extended":
        cols += [
            "tcp_syn_count", "tcp_fin_count", "tcp_rst_count",
            "iat_mean", "iat_std", "bytes_per_packet", "packets_per_second",
        ]
    return df[cols].astype(float)


def inject_synthetic(
    df: pd.DataFrame,
    ratio: float = 0.02,
    rng_seed: int = 42,
) -> pd.DataFrame:
    """Inject synthetic outliers into the feature matrix.

    A small fraction of synthetic points are drawn far outside the
    empirical distribution of each feature (based on the 5th and 95th
    percentiles).  These points encourage the Isolation Forest to assign
    low scores to extreme values.  When ``ratio`` is zero or the
    DataFrame is empty, the input DataFrame is returned unchanged.
    """
    if ratio <= 0 or df.empty:
        return df
    rng = np.random.default_rng(rng_seed)
    n = max(1, int(len(df) * ratio))
    cols = df.columns
    q_hi = df.quantile(0.95)
    q_lo = df.quantile(0.05)
    synth = []
    for _ in range(n):
        row = {}
        for c in cols:
            span = max(1e-9, float(q_hi[c] - q_lo[c]))
            # Draw well above the 95th percentile to ensure anomaly
            row[c] = float(q_hi[c] + 5.0 * span * rng.random())
        synth.append(row)
    df_s = pd.concat([df, pd.DataFrame(synth)], ignore_index=True)
    return df_s


def _columns_for(feature_set: str) -> List[str]:
    cols = [
        "bidirectional_packets", "bidirectional_bytes", "mean_packet_size",
        "std_packet_size", "flow_duration",
    ]
    if feature_set == "extended":
        cols += [
            "tcp_syn_count", "tcp_fin_count", "tcp_rst_count",
            "iat_mean", "iat_std", "bytes_per_packet", "packets_per_second",
        ]
    return cols


def _calibrate_contamination(
    Xs: np.ndarray,
    y: Optional[np.ndarray],
    candidates: List[float],
    random_state: int = 42,
) -> float:
    """Select the best contamination parameter using a simple F1 grid search.

    If labels ``y`` are provided, the data is split into a training and
    validation subset.  Synthetic points are handled by appending ones
    to the labels for the synthetic rows.  The contamination value with
    the highest F1 score on the validation set is returned.  If no
    labels are provided, the first candidate is used.
    """
    if y is None:
        return candidates[0]
    # Construct labels matching the synthetic injection if present
    # (we assume synthetic points appear at the end of the array)
    n_original = len(y)
    # Build y_ext such that any extra rows beyond the original are labelled as anomalies (1)
    def fit_and_score(cont: float) -> float:
        m = IsolationForest(
            n_estimators=200,
            max_samples="auto",
            contamination=cont,
            random_state=random_state,
            n_jobs=-1,
        )
        m.fit(Xtr)
        s = m.decision_function(Xval)
        pred = (s < 0).astype(int)
        tp = int(((pred == 1) & (yval == 1)).sum())
        fp = int(((pred == 1) & (yval == 0)).sum())
        fn = int(((pred == 0) & (yval == 1)).sum())
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        return 0.0 if (precision + recall) == 0 else (2 * precision * recall / (precision + recall))
    # Stratify only if there is at least one anomaly label
    strat = (y if y.sum() > 0 else None)
    Xtr, Xval, ytr, yval = train_test_split(
        Xs, y, test_size=0.2, random_state=random_state, stratify=strat
    )
    best_c = candidates[0]
    best_f1 = -1.0
    for c in candidates:
        f1 = fit_and_score(c)
        if f1 > best_f1:
            best_f1 = f1
            best_c = c
    return best_c


def train(csv_path: str, cfg_path: str, out_dir: str) -> str:
    """Train an Isolation Forest model and persist it to disk.

    Parameters
    ----------
    csv_path: str
        Path to the CSV file containing flows and (optionally) labels.
    cfg_path: str
        Path to a YAML configuration file (see ``load_config``).
    out_dir: str
        Directory where the model and threshold files should be written.

    Returns
    -------
    str
        The path to the written model file.
    """
    cfg = load_config(cfg_path)
    logger = get_logger("train", cfg["logs_dir"], "train.log")
    feature_set = cfg.get("feature_set", "extended")
    contamination_default = float(cfg.get("contamination", 0.02))

    df = pd.read_csv(csv_path)
    if df.empty:
        raise RuntimeError("Dataset is empty – nothing to train on")
    X = _select_numeric(df, feature_set)
    # Extract labels if present; assume 1 = anomaly, 0 = benign
    y: Optional[np.ndarray] = df["label"].values if "label" in df.columns else None
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X.values)
    # Inject synthetic outliers
    Xs_df = pd.DataFrame(Xs, columns=X.columns)
    Xs_inj = inject_synthetic(Xs_df, ratio=0.02)
    # If labels present, extend labels array to account for synthetic points (label 1 for synthetic)
    y_inj: Optional[np.ndarray] = None
    if y is not None:
        extra = len(Xs_inj) - len(Xs)
        if extra > 0:
            y_inj = np.concatenate([y, np.ones(extra, dtype=int)])
        else:
            y_inj = y
    # Calibration of contamination parameter
    candidates = [0.005, 0.01, 0.02, 0.05]
    best_cont = _calibrate_contamination(Xs_inj.values, y_inj, candidates) if y_inj is not None else contamination_default
    # Train the Isolation Forest
    model = IsolationForest(
        n_estimators=200,
        max_samples="auto",
        contamination=best_cont,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(Xs_inj.values)
    # Persist model and scaler
    model_path, latest_path = save_model(model, scaler, out_dir)
    # Compute thresholds: use training scores to set red_threshold; yellow fixed at 0
    try:
        scores_train = model.decision_function(Xs)
        red_threshold: float
        if y is not None and (y == 0).sum() > 0:
            benign_scores = scores_train[y == 0]
            # Choose threshold such that at most ~1% of benign flows are mislabelled (1st percentile)
            candidate = float(np.percentile(benign_scores, 1) - 1e-3)
            red_threshold = float(min(candidate, -0.02))
        else:
            red_threshold = float(np.min(scores_train) - 0.05)
    except Exception:
        red_threshold = -0.1
    yellow_threshold = 0.0
    thresholds_path = os.path.join(out_dir, "thresholds.json")
    try:
        with open(thresholds_path, "w", encoding="utf-8") as f_thr:
            json.dump({"red_threshold": red_threshold, "yellow_threshold": yellow_threshold}, f_thr, indent=2)
    except Exception:
        # Do not fail training on threshold write errors
        pass
    # Model card metadata
    card = {
        "git_hash": get_git_hash(short=False),
        "feature_set": feature_set,
        "contamination": contamination_default,
        "n_estimators": 200,
        "train_rows": int(len(df)),
        "columns_numeric": list(X.columns),
    }
    ensure_dirs(out_dir)
    try:
        with open(os.path.join(out_dir, f"model_card_{get_git_hash()}.json"), "w", encoding="utf-8") as f:
            json.dump(card, f, indent=2)
    except Exception:
        pass
    logger.info(f"Model trained → {model_path} (contamination={best_cont})")
    return model_path


def main() -> None:
    """Console entry point for the training script."""
    ap = argparse.ArgumentParser(description="Train an Isolation Forest on a CSV of network flows")
    ap.add_argument("--csv", required=True, help="Path to CSV file with flow features and optional labels")
    ap.add_argument("--config", default="config/config.yml", help="Path to configuration YAML file")
    ap.add_argument("--out", default="./models", help="Output directory for the trained model")
    args = ap.parse_args()
    ensure_dirs(args.out)
    train(args.csv, args.config, args.out)


if __name__ == "__main__":
    main()