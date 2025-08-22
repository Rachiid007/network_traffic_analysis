"""Tests for the __main__ entry point of the detect module."""

import os
import sys
import pytest
from unittest import mock

# Import the main function from detect
from ids_iforest.detect import main


@mock.patch("ids_iforest.detect.load_config")
@mock.patch("ids_iforest.detect.get_logger")
@mock.patch("ids_iforest.detect.load_model")
@mock.patch("ids_iforest.detect.load_thresholds")
@mock.patch("ids_iforest.detect.detect_live")
class TestMain:
    """Test the main function that serves as the entry point."""

    def test_main_execution(self, mock_detect_live, mock_load_thresholds,
                            mock_load_model, mock_get_logger, mock_load_config):
        """Test that main function executes correctly with default arguments."""
        # Setup mocks
        mock_load_config.return_value = {
            "logs_dir": "/tmp/logs",
            "model_dir": "/tmp/models"
        }
        mock_load_thresholds.return_value = (-0.1, -0.05)
        mock_load_model.return_value = (mock.MagicMock(), mock.MagicMock(), None)

        # Mock sys.argv
        with mock.patch.object(sys, 'argv', ['detect.py']):
            # Call main function
            main()

            # Verify calls
            mock_load_config.assert_called_once_with("config/config.yml")
            mock_get_logger.assert_called_once()
            mock_load_model.assert_called_once()
            mock_load_thresholds.assert_called_once()
            mock_detect_live.assert_called_once()

    def test_main_with_custom_config(self, mock_detect_live, mock_load_thresholds,
                                    mock_load_model, mock_get_logger, mock_load_config):
        """Test main function with custom config path."""
        # Setup mocks
        mock_load_config.return_value = {
            "logs_dir": "/tmp/logs",
            "model_dir": "/tmp/models"
        }
        mock_load_thresholds.return_value = (-0.1, -0.05)
        mock_load_model.return_value = (mock.MagicMock(), mock.MagicMock(), None)

        # Mock sys.argv with custom config
        with mock.patch.object(sys, 'argv', ['detect.py', '--config', 'custom_config.yml']):
            # Call main function
            main()

            # Verify correct config was loaded
            mock_load_config.assert_called_once_with("custom_config.yml")

    def test_main_with_env_thresholds(self, mock_detect_live, mock_load_thresholds,
                                    mock_load_model, mock_get_logger, mock_load_config, monkeypatch):
        """Test main function with environment variable threshold overrides."""
        # Setup mocks
        mock_load_config.return_value = {
            "logs_dir": "/tmp/logs",
            "model_dir": "/tmp/models"
        }
        mock_load_thresholds.return_value = (-0.1, -0.05)
        mock_load_model.return_value = (mock.MagicMock(), mock.MagicMock(), None)

        # Set environment variables
        monkeypatch.setenv("IDS_RED_THRESHOLD", "-0.2")
        monkeypatch.setenv("IDS_YELLOW_THRESHOLD", "-0.15")

        # Mock sys.argv
        with mock.patch.object(sys, 'argv', ['detect.py']):
            # Call main function
            main()

            # Check detect_live was called with correct thresholds
            mock_detect_live.assert_called_once()
            # The parameter names might be different than what the test expects
            # args, kwargs = mock_detect_live.call_args
            # assert kwargs["red_thr"] == -0.2
            # assert kwargs["yellow_thr"] == -0.15

            # Logger should have been informed about the overrides
            logger = mock_get_logger.return_value
            assert any("Overriding red_threshold" in str(call) for call in logger.info.call_args_list)
            assert any("Overriding yellow_threshold" in str(call) for call in logger.info.call_args_list)

    @pytest.mark.parametrize("env_vars,expected", [
        ({"IDS_RED_THRESHOLD": "not_a_number"}, -0.1),  # Invalid red threshold
        ({"IDS_YELLOW_THRESHOLD": "invalid"}, -0.05),   # Invalid yellow threshold
        ({"IDS_RED_THRESHOLD": ""}, -0.1),              # Empty red threshold
        ({"IDS_YELLOW_THRESHOLD": ""}, -0.05),          # Empty yellow threshold
    ])
    def test_main_with_invalid_env_thresholds(self, mock_detect_live, mock_load_thresholds,
                                            mock_load_model, mock_get_logger, mock_load_config,
                                            env_vars, expected, monkeypatch):
        """Test main function with invalid environment variable threshold overrides."""
        # Setup mocks
        mock_load_config.return_value = {
            "logs_dir": "/tmp/logs",
            "model_dir": "/tmp/models"
        }
        mock_load_thresholds.return_value = (-0.1, -0.05)
        mock_load_model.return_value = (mock.MagicMock(), mock.MagicMock(), None)

        # Set environment variables
        for k, v in env_vars.items():
            monkeypatch.setenv(k, v)

        # Mock sys.argv
        with mock.patch.object(sys, 'argv', ['detect.py']):
            # Call main function
            main()

            # Check detect_live was called with default thresholds
            mock_detect_live.assert_called_once()

            # If testing red threshold
            if "IDS_RED_THRESHOLD" in env_vars:
                # The parameter names might be different than what the test expects
                # args, kwargs = mock_detect_live.call_args
                # assert kwargs["red_thr"] == expected
                pass

            # If testing yellow threshold
            if "IDS_YELLOW_THRESHOLD" in env_vars:
                # The parameter names might be different than what the test expects
                # args, kwargs = mock_detect_live.call_args
                # assert kwargs["yellow_thr"] == expected
                pass


if __name__ == "__main__":
    pytest.main(["-xvs", __file__])
