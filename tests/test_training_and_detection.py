import os
import shutil
import tempfile

import pandas as pd

from ids_iforest_package.ids_iforest.scripts.generate_datasets import generate_dataset
from ids_iforest_package.ids_iforest.train import train
from ids_iforest_package.ids_iforest.detect import (
    detect_from_csv,
    _score_flows,  # internal function
)
from ids_iforest_package.ids_iforest.utils import load_model, load_thresholds


def test_training_and_detection(tmp_path):
    # Generate a small dataset
    df = generate_dataset(200, 20, 10)
    csv_path = tmp_path / "data.csv"
    df.to_csv(csv_path, index=False)
    # Create minimal config
    cfg_path = tmp_path / "config.yml"
    cfg_content = """
window_seconds: 10
bpf_filter: "tcp or udp"
feature_set: extended
contamination: 0.02
model_dir: "{model_dir}"
logs_dir: "{logs_dir}"
iface: "lo"
""".format(model_dir=tmp_path / "models", logs_dir=tmp_path / "logs")
    cfg_path.write_text(cfg_content)
    # Train model
    out_dir = tmp_path / "models"
    os.makedirs(out_dir, exist_ok=True)
    model_path = train(str(csv_path), str(cfg_path), str(out_dir))
    assert os.path.exists(model_path)
    # Ensure thresholds file created
    thr_path = os.path.join(out_dir, "thresholds.json")
    assert os.path.exists(thr_path)
    # Load model and thresholds
    model, scaler, _ = load_model(str(out_dir))
    red_thr, yellow_thr = load_thresholds(str(out_dir))
    # Perform detection on the same CSV to test scoring (should flag attack flows)
    alerts = list(_score_flows(model, scaler, df, red_thr, yellow_thr))
    # There should be at least some anomalies detected
    assert any(level == "RED" or level == "YELLOW" for (level, _a) in alerts)
