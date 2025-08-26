# IDS-IForest

Network intrusion detection system based on Isolation Forest and PyShark.

## Overview

This package provides tools for network traffic analysis and anomaly detection using machine learning. It uses the Isolation Forest algorithm to detect unusual network behavior that may indicate potential security threats.

For complete documentation and usage examples, please refer to the [main project README](../README.md).

## Quick Installation

```bash
pip install ids-iforest
```

Or for development:

```bash
pip install -e .
```

## Available Commands

After installation, the following commands will be available:

* `ids-iforest-train` – Train an Isolation Forest model on flow data
* `ids-iforest-detect` – Run anomaly detection (live/PCAP/CSV)
* `ids-iforest-capture` – Capture network traffic to flows CSV
* `ids-iforest-pcap2csv` – Convert PCAP files to flows CSV
* `ids-iforest-generate` – Generate synthetic datasets for testing

## Dependencies

- Python 3.10 or newer
- tshark (for live capture)
- scikit-learn, pandas, numpy, pyyaml, colorama, joblib

## License

MIT - See the LICENSE file for details.
