import os
import pandas as pd
from sklearn.ensemble import IsolationForest
from src.features.build_features import build_features
from src.models.train import split_Xy
from sklearn.preprocessing import StandardScaler

def test_train_smoke(tmp_path):
    # petit jeu synthétique
    df = pd.DataFrame({
        "flow_duration": [1,2,3,4,10,20],
        "fwd_pkts": [10,12,9,11,100,120],
        "bwd_pkts": [8,7,9,10,2,1],
        "fwd_bytes": [1000,1200,900,1100,8000,12000],
        "bwd_bytes": [900,800,950,1000,200,100],
        "label": ["Benign","Benign","Benign","Benign","Attack","Attack"]
    })
    proc = build_features(df)
    X, y, cols = split_Xy(proc)
    scaler = StandardScaler().fit(X.values)
    Xs = scaler.transform(X.values)

    model = IsolationForest(contamination=0.3, random_state=0).fit(Xs)
    y_pred = (model.predict(Xs) == -1).astype(int)
    assert y_pred.sum() >= 1  # au moins une anomalie détectée

    # save quick
    model_path = tmp_path / "model.pkl"
    scaler_path = tmp_path / "scaler.pkl"
    import joblib
    joblib.dump(model, model_path)
    joblib.dump({"scaler": scaler, "columns": cols}, scaler_path)
    assert os.path.exists(model_path)
    assert os.path.exists(scaler_path)
