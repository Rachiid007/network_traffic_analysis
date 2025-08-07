#!/usr/bin/env python3
import argparse
import json
import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
import joblib

def split_Xy(df: pd.DataFrame):
    y = None
    if "label" in df.columns:
        y = (df["label"].astype(str) != "Benign").astype(int).values  # 1=Attack, 0=Benign
        X = df.drop(columns=["label"])
    else:
        X = df
    # garde uniquement numérique
    num_cols = [c for c in X.columns if pd.api.types.is_numeric_dtype(X[c])]
    X = X[num_cols].astype(float)
    return X, y, num_cols

def main():
    ap = argparse.ArgumentParser(description="Train IsolationForest on processed CSV.")
    ap.add_argument("--data", required=True)
    ap.add_argument("--model", required=True)
    ap.add_argument("--scaler", required=True)
    ap.add_argument("--metrics", required=True)
    ap.add_argument("--max_rows", type=int, default=0, help="Cap lignes pour CI rapide (0=pas de cap)")
    ap.add_argument("--contamination", type=float, default=0.05)
    args = ap.parse_args()

    os.makedirs(os.path.dirname(args.model), exist_ok=True)

    df = pd.read_csv(args.data)
    if args.max_rows and args.max_rows > 0:
        df = df.head(args.max_rows).copy()

    X, y, cols = split_Xy(df)

    # scaling
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X.values)

    # model
    model = IsolationForest(
        n_estimators=150,
        contamination=args.contamination,
        random_state=42,
        n_jobs=-1,
    )
    model.fit(Xs)

    # save
    joblib.dump(model, args.model)
    joblib.dump({"scaler": scaler, "columns": cols}, args.scaler)

    # metrics
    metrics = {
        "n_rows": int(X.shape[0]),
        "n_features": int(X.shape[1]),
        "contamination": args.contamination
    }

    if y is not None:
        y_pred = (model.predict(Xs) == -1).astype(int)  # 1 = anomaly predicted
        cm = confusion_matrix(y, y_pred, labels=[0,1]).tolist()
        rep = classification_report(y, y_pred, target_names=["Benign","Attack"], output_dict=True)
        metrics.update({
            "confusion_matrix":[["TN","FP"],["FN","TP"]],
            "cm_values": cm,
            "precision": rep["weighted avg"]["precision"],
            "recall": rep["weighted avg"]["recall"],
            "f1": rep["weighted avg"]["f1-score"],
            "support": rep["weighted avg"]["support"]
        })

    with open(args.metrics, "w") as f:
        json.dump(metrics, f, indent=2)

    print(f"[train] model -> {args.model}")
    print(f"[train] scaler -> {args.scaler}")
    print(f"[train] metrics -> {args.metrics}")
    if y is not None:
        print(f"[train] F1={metrics['f1']:.3f}, Precision={metrics['precision']:.3f}, Recall={metrics['recall']:.3f}")

if __name__ == "__main__":
    main()
