#!/usr/bin/env python3
import argparse
import os
import pandas as pd
import numpy as np

def generate_synthetic(n_rows=3000, anomaly_ratio=0.05, seed=42):
    rng = np.random.default_rng(seed)
    n_anom = int(n_rows * anomaly_ratio)
    n_norm = n_rows - n_anom

    # Features simples type "flow"
    def flows(n, high=False):
        # normal: distributions modérées; high: valeurs extrêmes
        dur = rng.gamma(shape=2.0, scale=0.8, size=n) * (10 if high else 1)
        fwd_pkts = rng.poisson(lam=10 if not high else 60, size=n).clip(1, None)
        bwd_pkts = rng.poisson(lam=8 if not high else 40, size=n)
        fwd_bytes = (fwd_pkts * rng.integers(60, 800, size=n)).astype(float)
        bwd_bytes = (np.maximum(bwd_pkts, 1) * rng.integers(60, 800, size=n)).astype(float)
        syn = rng.binomial(n=1 if not high else 3, p=0.3 if not high else 0.9, size=n)
        ack = rng.binomial(n=1, p=0.8, size=n)
        psh = rng.binomial(n=1, p=0.1 if not high else 0.5, size=n)
        rst = rng.binomial(n=1, p=0.05 if not high else 0.3, size=n)
        return pd.DataFrame({
            "flow_duration": dur,
            "fwd_pkts": fwd_pkts,
            "bwd_pkts": bwd_pkts,
            "fwd_bytes": fwd_bytes,
            "bwd_bytes": bwd_bytes,
            "syn_flag_cnt": syn,
            "ack_flag_cnt": ack,
            "psh_flag_cnt": psh,
            "rst_flag_cnt": rst
        })

    df_norm = flows(n_norm, high=False)
    df_norm["label"] = "Benign"

    df_anom = flows(n_anom, high=True)
    df_anom["label"] = "Attack"

    df = pd.concat([df_norm, df_anom], ignore_index=True)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)
    return df

def main():
    ap = argparse.ArgumentParser(description="Make dataset (copy or generate).")
    ap.add_argument("--input", required=True, help="Chemin vers data/sample.csv (si présent).")
    ap.add_argument("--output", required=True, help="Chemin de sortie (ex: data/raw.csv).")
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.output), exist_ok=True)

    if os.path.exists(args.input):
        df = pd.read_csv(args.input)
    else:
        df = generate_synthetic()
    df.to_csv(args.output, index=False)
    print(f"[make_dataset] Wrote {args.output} with shape {df.shape}")

if __name__ == "__main__":
    main()
