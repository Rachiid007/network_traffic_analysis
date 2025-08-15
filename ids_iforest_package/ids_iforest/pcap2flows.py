"""Convert a PCAP file into a flows CSV file.

This script reads packets from a PCAP using PyShark, aggregates them
into bidirectional flows using the same logic as detection, and writes
the resulting feature vectors to a CSV.  It is useful for preparing
training data from offline captures.
"""

from __future__ import annotations

import argparse
from typing import Dict, Any, Tuple, Optional

try:
    import pyshark  # type: ignore
except Exception:
    pyshark = None  # type: ignore

import pandas as pd  # type: ignore

from .utils import load_config, aggregate_packets_to_flows, flows_to_dataframe

__all__ = ["main"]


def pcap_to_dataframe(
    pcap_path: str,
    cfg: Dict[str, Any],
) -> pd.DataFrame:
    """Read a PCAP and return a DataFrame of aggregated flows."""
    if pyshark is None:
        raise RuntimeError("pyshark is not installed – cannot process PCAPs")
    window = cfg["window_seconds"]
    feature_set = cfg.get("feature_set", "extended")
    cap = pyshark.FileCapture(
        pcap_path,
        only_summaries=False,
        keep_packets=False,
        decode_as={"tcp.port==80": "http"},
    )
    flows: Dict[Tuple[int, Tuple[Any, Any, str]], Dict[str, Any]] = {}
    base_ts: Optional[float] = None
    for pkt in cap:
        try:
            ts = float(pkt.frame_info.time_epoch)
        except Exception:
            continue
        if base_ts is None:
            base_ts = ts
        # Aggregate this single packet
        f = aggregate_packets_to_flows([pkt], window_seconds=window, base_ts=base_ts)
        for k, st in f.items():
            if k in flows:
                existing = flows[k]
                existing["packets"] += st["packets"]
                existing["bytes"] += st["bytes"]
                existing["sizes"].extend(st["sizes"])
                existing["tcp_syn"] += st["tcp_syn"]
                existing["tcp_fin"] += st["tcp_fin"]
                existing["tcp_rst"] += st["tcp_rst"]
                existing["iat"].extend(st["iat"])
                existing["first_ts"] = min(existing["first_ts"], st["first_ts"])
                existing["last_ts"] = max(existing["last_ts"], st["last_ts"])
            else:
                flows[k] = st
    cap.close()
    df = flows_to_dataframe(flows, feature_set)
    return df


def main() -> None:
    """Entry point for ids-iforest-pcap2csv console script."""
    ap = argparse.ArgumentParser(description="Aggregate flows from a PCAP into a CSV")
    ap.add_argument(
        "--config", default="config/config.yml", help="Path to configuration YAML file"
    )
    ap.add_argument("--pcap", required=True, help="PCAP file to process")
    ap.add_argument("--out", required=True, help="Output CSV file")
    args = ap.parse_args()
    cfg = load_config(args.config)
    df = pcap_to_dataframe(args.pcap, cfg)
    df.to_csv(args.out, index=False)
    print(f"Wrote {len(df)} flows to {args.out}")


if __name__ == "__main__":  # pragma: no cover
    main()
