"""Tests for the anomaly detection functionality in the ids_iforest package.

These tests focus on the core detection logic, flow processing, and alert generation
without requiring actual network traffic capture.
"""

import os
import tempfile
import pandas as pd
import numpy as np
import pytest
from unittest import mock

from ids_iforest.detect import (
    _score_flows,
    _write_alert_csv,
    _process_dataframe,
    _flows_to_df,
    _flag_to_int
)


class TestScoringFunctions:
    """Tests for flow scoring and anomaly detection functions."""

    def test_score_flows_empty_dataframe(self):
        """Test that _score_flows handles empty dataframes gracefully."""
        model = mock.MagicMock()
        scaler = mock.MagicMock()
        df = pd.DataFrame()

        results = list(_score_flows(model, scaler, df, -0.1, -0.05))
        assert results == []

    def test_score_flows_no_anomalies(self):
        """Test that _score_flows returns no alerts when scores are above thresholds."""
        # Mock model to return scores above thresholds
        model = mock.MagicMock()
        model.decision_function.return_value = np.array([0.1, 0.2])

        # Mock scaler (just passes through values)
        scaler = mock.MagicMock()
        scaler.transform.return_value = np.array([[1, 2, 3, 4, 5], [6, 7, 8, 9, 10]])

        # Create test dataframe
        df = pd.DataFrame({
            "src_ip": ["192.168.1.1", "192.168.1.2"],
            "dst_ip": ["10.0.0.1", "10.0.0.2"],
            "src_port": [12345, 23456],
            "dst_port": [80, 443],
            "protocol": ["tcp", "udp"],
            "bidirectional_packets": [10, 20],
            "bidirectional_bytes": [1000, 2000],
            "mean_packet_size": [100, 100],
            "std_packet_size": [10, 20],
            "flow_duration": [0.5, 1.0]
        })

        results = list(_score_flows(model, scaler, df, -0.1, -0.05))
        assert results == []

        # Verify scaler and model were called correctly
        scaler.transform.assert_called_once()
        model.decision_function.assert_called_once()

    def test_score_flows_with_anomalies(self):
        """Test that _score_flows correctly identifies anomalies based on thresholds."""
        # Mock model to return scores with some below thresholds
        model = mock.MagicMock()
        model.decision_function.return_value = np.array([-0.2, -0.07, 0.1])

        # Mock scaler
        scaler = mock.MagicMock()
        scaler.transform.return_value = np.array([[1, 2, 3, 4, 5], [6, 7, 8, 9, 10], [11, 12, 13, 14, 15]])

        # Create test dataframe with basic and extended features
        df = pd.DataFrame({
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

        results = list(_score_flows(model, scaler, df, -0.1, -0.05))

        # Should have two anomalies: one RED (-0.2 < -0.1) and one YELLOW (-0.07 < -0.05)
        assert len(results) == 2

        # Check the RED alert
        level, alert = results[0]
        assert level == "RED"
        assert alert["src_ip"] == "192.168.1.1"
        assert alert["dst_ip"] == "10.0.0.1"
        assert alert["src_port"] == 12345
        assert alert["dst_port"] == 80
        assert alert["protocol"] == "tcp"
        assert alert["score"] == -0.2
        assert alert["level"] == "RED"

        # Check the YELLOW alert
        level, alert = results[1]
        assert level == "YELLOW"
        assert alert["src_ip"] == "192.168.1.2"
        assert alert["dst_ip"] == "10.0.0.2"
        assert alert["src_port"] == 23456
        assert alert["dst_port"] == 443
        assert alert["protocol"] == "udp"
        assert alert["score"] == -0.07
        assert alert["level"] == "YELLOW"


class TestAlertPersistence:
    """Tests for alert persistence functionality."""

    def test_write_alert_csv_new_file(self):
        """Test writing alerts to a new CSV file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "alerts.csv")

            # Create some test alerts
            alerts = [
                ("RED", {
                    "timestamp": "2025-08-22T12:00:00",
                    "src_ip": "192.168.1.1",
                    "dst_ip": "10.0.0.1",
                    "src_port": 12345,
                    "dst_port": 80,
                    "protocol": "tcp",
                    "score": -0.2,
                    "level": "RED"
                }),
                ("YELLOW", {
                    "timestamp": "2025-08-22T12:01:00",
                    "src_ip": "192.168.1.2",
                    "dst_ip": "10.0.0.2",
                    "src_port": 23456,
                    "dst_port": 443,
                    "protocol": "udp",
                    "score": -0.07,
                    "level": "YELLOW"
                })
            ]

            _write_alert_csv(alerts, csv_path)

            # Verify the file exists and has correct content
            assert os.path.exists(csv_path)

            # Read back and verify
            df = pd.read_csv(csv_path)
            assert len(df) == 2
            assert list(df.columns) == [
                "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
                "protocol", "score", "level"
            ]
            assert df["level"].tolist() == ["RED", "YELLOW"]

    def test_write_alert_csv_append(self):
        """Test appending alerts to an existing CSV file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "alerts.csv")

            # First write
            alerts1 = [
                ("RED", {
                    "timestamp": "2025-08-22T12:00:00",
                    "src_ip": "192.168.1.1",
                    "dst_ip": "10.0.0.1",
                    "src_port": 12345,
                    "dst_port": 80,
                    "protocol": "tcp",
                    "score": -0.2,
                    "level": "RED"
                })
            ]
            _write_alert_csv(alerts1, csv_path)

            # Second write (append)
            alerts2 = [
                ("YELLOW", {
                    "timestamp": "2025-08-22T12:01:00",
                    "src_ip": "192.168.1.2",
                    "dst_ip": "10.0.0.2",
                    "src_port": 23456,
                    "dst_port": 443,
                    "protocol": "udp",
                    "score": -0.07,
                    "level": "YELLOW"
                })
            ]
            _write_alert_csv(alerts2, csv_path)

            # Read back and verify
            df = pd.read_csv(csv_path)
            assert len(df) == 2
            assert df["level"].tolist() == ["RED", "YELLOW"]

    @mock.patch("ids_iforest.detect._score_flows")
    @mock.patch("ids_iforest.detect._write_alert_csv")
    @mock.patch("ids_iforest.logging_utils.append_json_alert")
    def test_process_dataframe(self, mock_append_json, mock_write_csv, mock_score_flows):
        """Test the _process_dataframe function that ties scoring and persistence."""
        # Setup mocks
        mock_score_flows.return_value = [
            ("RED", {
                "timestamp": "2025-08-22T12:00:00",
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.1",
                "src_port": 12345,
                "dst_port": 80,
                "protocol": "tcp",
                "score": -0.2,
                "level": "RED"
            })
        ]

        # Mock logger
        mock_logger = mock.MagicMock()

        # Test dataframe with all required columns to avoid KeyError
        df = pd.DataFrame({
            "src_ip": ["192.168.1.1"],
            "dst_ip": ["10.0.0.1"],
            "src_port": [12345],
            "dst_port": [80],
            "protocol": ["tcp"],
            "bidirectional_packets": [10],
            "bidirectional_bytes": [1000],
            "mean_packet_size": [100],
            "std_packet_size": [10],
            "flow_duration": [0.5],
            # Adding the extended columns that were missing
            "tcp_syn_count": [1],
            "tcp_fin_count": [1],
            "tcp_rst_count": [0],
            "iat_mean": [0.05],
            "iat_std": [0.01],
            "bytes_per_packet": [100],
            "packets_per_second": [20]
        })

        # Mock model and scaler
        model = mock.MagicMock()
        model.decision_function.return_value = [0.1]  # Return a non-empty scores array
        scaler = mock.MagicMock()
        scaler.transform.return_value = [[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]]

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, "alerts.csv")

            # Call the function
            _process_dataframe(df, model, scaler, -0.1, -0.05, mock_logger, csv_path)

            # Verify calls
            mock_score_flows.assert_called_once()
            mock_write_csv.assert_called_once()
            assert mock_append_json.call_count == 1
            assert mock_logger.info.call_count >= 2  # At least two info log calls
            assert mock_logger.error.call_count == 1  # One RED alert logged


class TestFlowProcessing:
    """Tests for flow processing and aggregation."""

    def test_flows_to_df_basic(self):
        """Test conversion of flow statistics to DataFrame with basic features."""
        # Create mock flows
        flows = {
            (1, "192.168.1.1", "10.0.0.1", 12345, 80, "tcp"): {
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.1",
                "src_port": 12345,
                "dst_port": 80,
                "protocol": "tcp",
                "packets": 10,
                "bytes": 1000,
                "sizes": [100] * 10,
                "first_ts": 1000.0,
                "last_ts": 1001.0,
                "tcp_syn": 1,
                "tcp_fin": 1,
                "tcp_rst": 0,
                "iat": [0.1] * 9,
            }
        }

        # Convert to DataFrame with basic features
        df = _flows_to_df(flows, "basic")

        # Verify the DataFrame
        assert len(df) == 1
        assert df["src_ip"].iloc[0] == "192.168.1.1"
        assert df["dst_ip"].iloc[0] == "10.0.0.1"
        assert df["src_port"].iloc[0] == 12345
        assert df["dst_port"].iloc[0] == 80
        assert df["protocol"].iloc[0] == "tcp"
        assert df["bidirectional_packets"].iloc[0] == 10
        assert df["bidirectional_bytes"].iloc[0] == 1000
        assert df["mean_packet_size"].iloc[0] == 100.0
        assert df["std_packet_size"].iloc[0] == 0.0
        assert df["flow_duration"].iloc[0] == 1.0

        # Verify extended features are not present
        assert "tcp_syn_count" not in df.columns

    def test_flows_to_df_extended(self):
        """Test conversion of flow statistics to DataFrame with extended features."""
        # Create mock flows
        flows = {
            (1, "192.168.1.1", "10.0.0.1", 12345, 80, "tcp"): {
                "src_ip": "192.168.1.1",
                "dst_ip": "10.0.0.1",
                "src_port": 12345,
                "dst_port": 80,
                "protocol": "tcp",
                "packets": 10,
                "bytes": 1000,
                "sizes": [90, 100, 110] + [100] * 7,
                "first_ts": 1000.0,
                "last_ts": 1001.0,
                "tcp_syn": 1,
                "tcp_fin": 1,
                "tcp_rst": 0,
                "iat": [0.1, 0.2] + [0.1] * 7,
            }
        }

        # Convert to DataFrame with extended features
        df = _flows_to_df(flows, "extended")

        # Verify the DataFrame
        assert len(df) == 1

        # Basic features
        assert df["src_ip"].iloc[0] == "192.168.1.1"
        assert df["protocol"].iloc[0] == "tcp"
        assert df["bidirectional_packets"].iloc[0] == 10
        assert df["bidirectional_bytes"].iloc[0] == 1000

        # Extended features
        assert df["tcp_syn_count"].iloc[0] == 1
        assert df["tcp_fin_count"].iloc[0] == 1
        assert df["tcp_rst_count"].iloc[0] == 0
        assert df["iat_mean"].iloc[0] == pytest.approx(0.11111, 0.001)  # 1/9 * (0.1*8 + 0.2)
        assert df["iat_std"].iloc[0] > 0  # There's some std deviation
        assert df["bytes_per_packet"].iloc[0] == 100.0
        assert df["packets_per_second"].iloc[0] == 10.0

    def test_flag_to_int(self):
        """Test conversion of various flag formats to integers."""
        # True values
        assert _flag_to_int("1") == 1
        assert _flag_to_int("True") == 1
        assert _flag_to_int("true") == 1
        assert _flag_to_int("T") == 1
        assert _flag_to_int("yes") == 1
        assert _flag_to_int("Y") == 1
        assert _flag_to_int("42") == 1  # Any non-zero integer is True

        # False values
        assert _flag_to_int("0") == 0
        assert _flag_to_int("False") == 0
        assert _flag_to_int("false") == 0
        assert _flag_to_int("F") == 0
        assert _flag_to_int("no") == 0
        assert _flag_to_int("N") == 0
        assert _flag_to_int("") == 0
        assert _flag_to_int(None) == 0

        # Edge cases
        assert _flag_to_int("  True  ") == 1  # whitespace
        assert _flag_to_int("0xFF") == 0  # non-parseable as int


@pytest.mark.parametrize(
    "feature_set",
    ["basic", "extended"]
)
def test_flows_to_df_empty(feature_set):
    """Test that _flows_to_df handles empty flow dictionaries correctly."""
    df = _flows_to_df({}, feature_set)
    assert isinstance(df, pd.DataFrame)
    assert df.empty


@mock.patch("ids_iforest.detect.subprocess.Popen")
@mock.patch("ids_iforest.detect._process_dataframe")
def test_detect_live_early_exit(mock_process_df, mock_popen, monkeypatch):
    """Test that detect_live handles early termination gracefully."""
    # This test just ensures the function handles early exits
    # without attempting to test the full live capture flow

    from ids_iforest.detect import detect_live

    # Mock configuration
    cfg = {
        "iface": "eth0",
        "bpf_filter": "tcp or udp",
        "window_seconds": 10,
        "feature_set": "extended"
    }

    # Mock objects
    model = mock.MagicMock()
    scaler = mock.MagicMock()
    logger = mock.MagicMock()

    # Create mock process that exits immediately
    mock_process = mock.MagicMock()
    mock_process.stdout = []  # Empty iterable
    mock_popen.return_value = mock_process

    # Mock shutil.which to return a path for tshark
    monkeypatch.setattr("shutil.which", lambda cmd: "/usr/bin/tshark" if cmd == "tshark" else None)

    with tempfile.TemporaryDirectory() as tmpdir:
        csv_path = os.path.join(tmpdir, "alerts.csv")

        # Run the function with mocked dependencies
        detect_live(cfg, model, scaler, -0.1, -0.05, logger, csv_path)

        # Verify that Popen was called with expected arguments
        mock_popen.assert_called_once()
        cmd_args = mock_popen.call_args[0][0]
        assert cmd_args[0].endswith("tshark")
        assert "-i" in cmd_args
        assert "eth0" in cmd_args


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])
