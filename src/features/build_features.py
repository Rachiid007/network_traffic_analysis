#!/usr/bin/env python3
import argparse
import os
import pandas as pd
import numpy as np

NUMERIC_EXCLUDE = {"label"}

def infer_numeric_columns(df: pd.DataFrame):
    # On garde les colonnes numériques; 'label' est conservée à part si présente
    numeric_cols = [c for c in df.columns if pd.api.types.is_numeric_dtype(df[c]) and c not in NUMERIC_EXCLUDE]
    return numeric_cols

def build_features(df: pd.DataFrame):
    # Nettoyage simple
    df = df.copy()
    if "label" in df.columns:
        y = df["label"].astype(str)
    else:
        y = None

    # Remplacement inf/nan
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    numeric_cols = infer_numeric_columns(df)
    X = df[numeric_cols].astype(float)

    # Petites features dérivées (exemples)
    if set(["fwd_bytes", "bwd_bytes"]).issubset(X.columns):
        X["down_up_ratio"] = (X["bwd_bytes"] + 1) / (X["fwd_bytes"] + 1)
    if set(["flow_duration", "fwd_pkts", "bwd_pkts"]).issubset(X.columns):
        X["pkts_per_sec"] = (X["fwd_pkts"] + X["bwd_pkts"]) / (X["flow_duration"] + 1e-3)

    # Capping léger (99e percentile) colonne par colonne
    capped = X.copy()
    for col in capped.columns:
        p99 = np.percentile(capped[col], 99)
        capped[col] = np.minimum(capped[col], p99)

    if y is not None:
        capped["label"] = y.values

    return capped

def main():
    ap = argparse.ArgumentParser(description="Build features from raw CSV.")
    ap.add_argument("--input", required=True, help="data/raw.csv")
    ap.add_argument("--output", required=True, help="data/processed.csv")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    df = pd.read_csv(args.input)
    out = build_features(df)
    out.to_csv(args.output, index=False)
    print(f"[build_features] Wrote {args.output} with shape {out.shape}")

if __name__ == "__main__":
    main()
