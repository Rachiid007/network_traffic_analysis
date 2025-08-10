import os
import pandas as pd

from ids_iforest_package.ids_iforest.scripts.generate_datasets import (
    generate_dataset,
    generate_benign,
    generate_syn_flood,
    generate_port_scan,
)


def test_generate_dataset_counts():
    df = generate_dataset(50, 10, 5)
    assert len(df) == 65
    # Ensure label distribution
    assert df["label"].sum() == 15
    assert ((df["label"] == 0).sum()) == 50
    assert ((df["label"] == 1).sum()) == 15