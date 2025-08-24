# IDS-IForest

Network intrusion detection system based on Isolation Forest and PyShark.

## Overview

This package provides tools for network traffic analysis and anomaly detection using machine learning. It uses the Isolation Forest algorithm to detect unusual network behavior that may indicate potential security threats.

## Features

- Train anomaly detection models on network traffic data
- Detect anomalies in live network traffic or PCAP files
- Convert PCAP files to flow-based CSV format
- Generate synthetic datasets for testing

## Installation

```bash
pip install ids-iforest
```

## Usage

### Training a model

```bash
ids-iforest-train --input data/train.csv --output models/ids_iforest.joblib
```

### Detecting anomalies

```bash
ids-iforest-detect --model models/ids_iforest.joblib --interface eth0
```

### Converting PCAP to CSV

```bash
ids-iforest-pcap2csv --input capture.pcap --output flows.csv
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
