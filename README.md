# pseudoIDS – Anomaly-based NIDS (Isolation Forest)

## Lancer en local
```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 1) Génère un dataset (ou placez data/sample.csv) puis features
python src/data/make_dataset.py --input data/sample.csv --output data/raw.csv
python src/features/build_features.py --input data/raw.csv --output data/processed.csv

# 2) Entraîne un modèle
python src/models/train.py --data data/processed.csv --model models/model.pkl --scaler models/scaler.pkl --metrics models/metrics.json --contamination 0.05

# 3) Smoke test (PCAP synthétique)
python src/predict/run_detector.py --model models/model.pkl --scaler models/scaler.pkl --out results.json --generate-sample-pcap
cat results.json
