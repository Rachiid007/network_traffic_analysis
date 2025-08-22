"""Conftest file for pytest configuration for ids_iforest tests."""

import os
import tempfile
import pytest
from unittest import mock

@pytest.fixture
def temp_log_dir():
    """Create a temporary directory for logs during tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create alerts.jsonl to avoid issues with tests that expect it
        alerts_jsonl = os.path.join(tmpdir, "alerts.jsonl")
        with open(alerts_jsonl, 'w') as f:
            pass
        yield tmpdir


@pytest.fixture
def mock_model_and_scaler():
    """Create mock model and scaler for testing."""
    model = mock.MagicMock()
    scaler = mock.MagicMock()
    return model, scaler


@pytest.fixture
def mock_logger():
    """Create a mock logger for testing."""
    return mock.MagicMock()


@pytest.fixture
def sample_dataframe():
    """Create a sample dataframe for testing."""
    import pandas as pd

    # Create a small dataframe with network flow data
    return pd.DataFrame({
        "src_ip": ["192.168.1.1", "192.168.1.2", "192.168.1.3"],
        "dst_ip": ["10.0.0.1", "10.0.0.2", "10.0.0.3"],
        "src_port": [12345, 23456, 34567],
        "dst_port": [80, 443, 8080],
        "protocol": ["tcp", "udp", "tcp"],
        "bidirectional_packets": [10, 20, 30],
        "bidirectional_bytes": [1000, 2000, 3000],
        "mean_packet_size": [100, 100, 100],
        "std_packet_size": [10, 20, 30],
        "flow_duration": [0.5, 1.0, 1.5],
        "tcp_syn_count": [1, 0, 2],
        "tcp_fin_count": [1, 0, 1],
        "tcp_rst_count": [0, 0, 0],
        "iat_mean": [0.05, 0.1, 0.15],
        "iat_std": [0.01, 0.02, 0.03],
        "bytes_per_packet": [100, 100, 100],
        "packets_per_second": [20, 20, 20]
    })


@pytest.fixture
def sample_config():
    """Create a sample configuration for testing."""
    return {
        "iface": "eth0",
        "bpf_filter": "tcp or udp",
        "window_seconds": 10,
        "feature_set": "extended",
        "logs_dir": "/tmp/logs",
        "model_dir": "/tmp/models"
    }
