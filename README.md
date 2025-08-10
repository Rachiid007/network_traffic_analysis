# IDS Isolation Forest Project

This repository contains an Intrusion Detection System (IDS) that uses
the Isolation Forest algorithm to detect anomalies in network traffic.
The project provides tools for capturing packets, aggregating them into
bidirectional flows, training a machine‑learning model and running
real‑time detection with a web interface.  It is packaged as a
pip‑installable Python module and can be orchestrated using
Docker Compose.

## Features

* **Aggregation**: Packets are aggregated into bidirectional flows
  based on the canonical 5‑tuple (source/destination IP/port and
  protocol) and a configurable time window.  Numeric features such
  as packet counts, bytes, durations and inter‑arrival times are
  extracted.
* **Model training**: A script to train an Isolation Forest on a CSV
  of flow features.  The contamination rate can be calibrated based
  on labelled data.  The trained model and scaler are saved to disk
  along with alert thresholds and a model card containing metadata.
* **Live and offline detection**: Detect anomalies from live network
  traffic, a PCAP file or a precomputed flows CSV.  Alerts are logged
  to both a file and a CSV for the web UI.
* **Web interface**: A lightweight Flask application displays recent
  alerts in real time.  The web UI automatically refreshes and
  highlights anomalies.
* **Dataset generation**: A helper script generates synthetic flows
  representing benign traffic and a couple of attack types (SYN
  flood and port scan).  This is useful for testing and
  demonstration when real datasets are unavailable.
* **Packaging and CI**: The project uses a modern `pyproject.toml`
  configuration and provides a GitLab CI pipeline with linting,
  unit tests and container build jobs.
* **Docker orchestration**: A `docker-compose.yml` orchestrates three
  services: a simple Nginx web server (victim), the IDS and a
  traffic generator (attacker).  Running `docker-compose up` will
  train the model (if not already present), start the IDS with its
  web UI and generate traffic to produce alerts.

## Getting started

### Prerequisites

* Docker and Docker Compose
* Python 3.11+ (only required if running outside of Docker)

### Installation

To install the Python package locally for development:

```bash
pip install -e ids_iforest_package
```

This will install the `ids-iforest-*` console scripts in your
environment.

### Training the model

Generate a synthetic dataset:

```bash
ids-iforest-generate --benign 1000 --syn-flood 200 --port-scan 200 --out data/train.csv
```

Train the model using the provided configuration:

```bash
ids-iforest-train --csv data/train.csv --config config/config.yml --out models
```

The trained model and thresholds will be saved in `models/`.

### Running detection

You can test detection on the same dataset:

```bash
ids-iforest-detect --csv data/train.csv --config config/config.yml
```

For live detection, simply run without file arguments:

```bash
ids-iforest-detect --config config/config.yml
```

### Starting the web interface

The combined server runs the live detector in a background thread and
serves the web UI on port 5000:

```bash
ids-iforest-server --config config/config.yml
```

Visit `http://localhost:5000` to view the alerts table.  Use
`--no-detector` if you only want to display existing alerts.

### Docker deployment

To run the complete system with Docker Compose:

```bash
docker-compose build
docker-compose up
```

This will build the IDS, web and attacker images and start the
services.  The IDS will expose its web UI on port 5000 and the
victim web server on port 8080.  Alerts will be written to the
`logs/alerts.csv` file.

## Future work

* Integration of real datasets such as CIC‑IDS 2017 for training
  and evaluation.
* Support for additional anomaly detection algorithms (One‑Class
  SVM, autoencoders, etc.).
* More sophisticated web UI with filtering and visualisation.
* Automated packaging and release pipeline.

## License

This project is licensed under the MIT license.  See `LICENSE` for
details.