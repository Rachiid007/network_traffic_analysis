"""Generate synthetic training datasets for the ids_iforest project.

This script creates CSV files containing artificial flow records for
benign and malicious traffic.  The synthetic data is meant to
exercise the Isolation Forest model during development.  It is not a
replacement for real labelled datasets like CIC‑IDS 2017, but it
provides a quick way to test training and detection logic on a modest
machine.

The generated flows include two categories of anomalies:

* SYN flood: very large numbers of packets with many SYN flags and
  short durations.
* Port scan: high connection rates to many destination ports with
  extremely low packet counts per flow.

Each flow has a ``label`` column set to 0 for benign or 1 for
malicious.  Numeric features follow the definitions used by
``flows_to_dataframe``.
"""

from __future__ import annotations

import argparse
import ipaddress
import random
from typing import List

import numpy as np  # type: ignore
import pandas as pd  # type: ignore

__all__ = ["main"]


def _random_ip(private: bool = True) -> str:
    """Return a random IPv4 address.

    When ``private`` is true, pick from RFC1918 ranges; otherwise pick
    from the public space.
    """
    if private:
        # Pick a private /16 randomly
        block = random.choice([(10, 8), (172, 12), (192, 16)])
        if block[0] == 10:
            octet1 = 10
            octet2 = random.randint(0, 255)
        elif block[0] == 172:
            octet1 = 172
            octet2 = random.randint(16, 31)
        else:
            octet1 = 192
            octet2 = 168
        octet3 = random.randint(0, 255)
        octet4 = random.randint(1, 254)
        return f"{octet1}.{octet2}.{octet3}.{octet4}"
    else:
        return str(ipaddress.IPv4Address(random.getrandbits(32)))


def generate_benign(n: int) -> pd.DataFrame:
    """Generate ``n`` benign flows with realistic random values."""
    rows: List[dict] = []
    for _ in range(n):
        pkt_count = random.randint(1, 50)
        total_bytes = pkt_count * random.randint(40, 1500)
        mean_ps = total_bytes / pkt_count
        std_ps = mean_ps * random.uniform(0.1, 0.5)
        duration = random.uniform(0.001, 5.0)
        row = {
            "window": 0,
            "src_ip": _random_ip(True),
            "dst_ip": _random_ip(False),
            "src_port": random.randint(1025, 65535),
            "dst_port": random.choice([80, 443, 22, 25, 53, 123]) if random.random() < 0.8 else random.randint(1, 65535),
            "protocol": random.choice(["tcp", "udp"]),
            "bidirectional_packets": pkt_count,
            "bidirectional_bytes": total_bytes,
            "mean_packet_size": mean_ps,
            "std_packet_size": std_ps,
            "flow_duration": duration,
            "tcp_syn_count": 0,
            "tcp_fin_count": 0,
            "tcp_rst_count": 0,
            "iat_mean": duration / pkt_count,
            "iat_std": (duration / pkt_count) * random.uniform(0.1, 0.5),
            "bytes_per_packet": total_bytes / pkt_count,
            "packets_per_second": pkt_count / duration,
            "label": 0,
        }
        rows.append(row)
    return pd.DataFrame(rows)


def generate_syn_flood(n: int) -> pd.DataFrame:
    """Generate ``n`` SYN‑flood attack flows."""
    rows: List[dict] = []
    for _ in range(n):
        pkt_count = random.randint(1000, 5000)
        total_bytes = pkt_count * random.randint(40, 80)
        duration = random.uniform(0.01, 1.0)
        row = {
            "window": 0,
            "src_ip": _random_ip(False),
            "dst_ip": _random_ip(True),
            "src_port": random.randint(1025, 65535),
            "dst_port": random.randint(1, 1024),
            "protocol": "tcp",
            "bidirectional_packets": pkt_count,
            "bidirectional_bytes": total_bytes,
            "mean_packet_size": total_bytes / pkt_count,
            "std_packet_size": random.uniform(0, 5),
            "flow_duration": duration,
            "tcp_syn_count": pkt_count,
            "tcp_fin_count": 0,
            "tcp_rst_count": 0,
            "iat_mean": duration / pkt_count,
            "iat_std": 0.0,
            "bytes_per_packet": total_bytes / pkt_count,
            "packets_per_second": pkt_count / duration,
            "label": 1,
        }
        rows.append(row)
    return pd.DataFrame(rows)


def generate_port_scan(n: int) -> pd.DataFrame:
    """Generate ``n`` port scan attack flows."""
    rows: List[dict] = []
    for _ in range(n):
        pkt_count = random.randint(1, 3)
        total_bytes = pkt_count * random.randint(40, 200)
        duration = random.uniform(0.0001, 0.01)
        row = {
            "window": 0,
            "src_ip": _random_ip(False),
            "dst_ip": _random_ip(True),
            "src_port": random.randint(1025, 65535),
            "dst_port": random.randint(1, 65535),
            "protocol": "tcp",
            "bidirectional_packets": pkt_count,
            "bidirectional_bytes": total_bytes,
            "mean_packet_size": total_bytes / pkt_count,
            "std_packet_size": 0.0,
            "flow_duration": duration,
            "tcp_syn_count": pkt_count,
            "tcp_fin_count": 0,
            "tcp_rst_count": 0,
            "iat_mean": duration / pkt_count,
            "iat_std": 0.0,
            "bytes_per_packet": total_bytes / pkt_count,
            "packets_per_second": pkt_count / duration,
            "label": 1,
        }
        rows.append(row)
    return pd.DataFrame(rows)


def generate_dataset(
    n_benign: int,
    n_syn_flood: int,
    n_port_scan: int,
) -> pd.DataFrame:
    """Combine benign and attack flows into a single shuffled DataFrame."""
    dfs = [
        generate_benign(n_benign),
        generate_syn_flood(n_syn_flood),
        generate_port_scan(n_port_scan),
    ]
    df = pd.concat(dfs, ignore_index=True)
    df = df.sample(frac=1.0, random_state=42).reset_index(drop=True)
    return df


def main() -> None:
    """Entry point for ids-iforest-generate console script."""
    ap = argparse.ArgumentParser(description="Generate synthetic training datasets for ids_iforest")
    ap.add_argument("--benign", type=int, default=1000, help="Number of benign flows")
    ap.add_argument("--syn-flood", type=int, default=100, help="Number of SYN flood attack flows")
    ap.add_argument("--port-scan", type=int, default=100, help="Number of port scan attack flows")
    ap.add_argument("--out", required=True, help="Output CSV file path")
    args = ap.parse_args()
    df = generate_dataset(args.benign, args.syn_flood, args.port_scan)
    df.to_csv(args.out, index=False)
    print(f"Generated dataset with {len(df)} flows → {args.out}")


if __name__ == "__main__":  # pragma: no cover
    main()
