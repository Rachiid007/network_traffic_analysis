import pandas as pd
import numpy as np
from src.features.build_features import build_features

def test_build_features_no_nan():
    df = pd.DataFrame({
        "flow_duration": [0.5, 2.0, np.inf],
        "fwd_pkts": [10, 0, 5],
        "bwd_pkts": [2, 1, 0],
        "fwd_bytes": [1000, 0, 200],
        "bwd_bytes": [500, 200, 0],
        "label": ["Benign", "Attack", "Benign"]
    })
    out = build_features(df)
    assert out.isna().sum().sum() == 0
    # colonnes dérivées présentes
    assert "down_up_ratio" in out.columns
    assert "pkts_per_sec" in out.columns
