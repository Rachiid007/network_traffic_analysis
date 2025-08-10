# ids_iforest/scripts/prepare_csecic2018.py
import argparse, glob, math, os
import pandas as pd
import numpy as np
from typing import Dict, Optional, Tuple

# Protocol mapping
PROTO_MAP = {6: "tcp", 17: "udp"}

# Acceptable (case-insensitive) synonyms for each logical field
SYNONYMS = {
    "flow_id": ["flow id", "flowid"],

    "src_ip":   ["src ip", "source ip", "src_ip"],
    "dst_ip":   ["dst ip", "destination ip", "dst_ip"],
    "src_port": ["src port", "source port", "src_port"],
    "dst_port": ["dst port", "destination port", "dst_port"],

    "protocol": ["protocol"],

    # durations & IAT (CICFlowMeter in microseconds)
    "flow_duration_us": ["flow duration", "flow duration(us)", "flow_duration"],
    "flow_iat_mean_us": ["flow iat mean", "flow iat mean(us)", "flow_iat_mean"],
    "flow_iat_std_us":  ["flow iat std",  "flow iat std(us)",  "flow_iat_std"],

    # packets / bytes (abrégé vs long)
    "fwd_pkts":  ["tot fwd pkts", "total fwd packets", "fwd packets", "fwd_pkts"],
    "bwd_pkts":  ["tot bwd pkts", "total backward packets", "bwd packets", "bwd_pkts"],
    "fwd_bytes": ["totlen fwd pkts", "total length of fwd packets", "fwd bytes", "fwd_bytes"],
    "bwd_bytes": ["totlen bwd pkts", "total length of bwd packets", "bwd bytes", "bwd_bytes"],

    # flags
    "syn": ["syn flag cnt", "syn flag count", "syn"],
    "fin": ["fin flag cnt", "fin flag count", "fin"],
    "rst": ["rst flag cnt", "rst flag count", "rst"],

    # std packet size in CICFlowMeter (Pkt Len Std)
    "pkt_len_std": ["pkt len std", "packet length std", "pkt length std"],

    "label_raw": ["label"],
}

# Patterns sometimes used by CICFlowMeter in Flow ID fields
FLOW_ID_PATTERNS = [
    r"^(?P<src_ip>[^:]+):(?P<src_port>\d+)-(?P<dst_ip>[^:]+):(?P<dst_port>\d+)-(?P<proto>.+)$",
    r"^(?P<src_ip>[^-]+)-(?P<dst_ip>[^-]+)-(?P<src_port>\d+)-(?P<dst_port>\d+)-(?P<proto>.+)$",
]

REQUIRED_CORE = ["protocol", "flow_duration_us", "fwd_pkts", "bwd_pkts", "fwd_bytes", "bwd_bytes", "label_raw"]

def _normcols(cols):
    # lower/strip; replace "/" by space; collapse spaces
    norm = {}
    for c in cols:
        k = str(c).strip().lower().replace("/", " ")
        k = " ".join(k.split())
        norm[k] = c
    return norm

def _pick(norm_map: Dict[str, str], names):
    for n in names:
        k = " ".join(n.strip().lower().split())
        if k in norm_map:
            return norm_map[k]
    return None

def _parse_flow_id(series: pd.Series):
    src_ip = pd.Series(["0.0.0.0"] * len(series))
    dst_ip = pd.Series(["0.0.0.0"] * len(series))
    src_port = pd.Series([0] * len(series))
    dst_port = pd.Series([0] * len(series))
    proto = pd.Series([None] * len(series))
    for pat in FLOW_ID_PATTERNS:
        m = series.astype(str).str.extract(pat, expand=True)
        # if all NaN, continue
        if m.isna().all().all():
            continue
        src_ip = m.get("src_ip", src_ip).fillna(src_ip)
        dst_ip = m.get("dst_ip", dst_ip).fillna(dst_ip)
        if "src_port" in m:
            src_port = pd.to_numeric(m["src_port"], errors="coerce").fillna(src_port).astype(int)
        if "dst_port" in m:
            dst_port = pd.to_numeric(m["dst_port"], errors="coerce").fillna(dst_port).astype(int)
        proto = m.get("proto", proto).fillna(proto)
        break
    return src_ip, dst_ip, src_port, dst_port, proto

def _select_columns(df: pd.DataFrame) -> Tuple[Dict[str, Optional[str]], Dict[str, str]]:
    norm = _normcols(df.columns)
    sel = {tgt: _pick(norm, srcs) for tgt, srcs in SYNONYMS.items()}
    missing = [k for k in REQUIRED_CORE if sel.get(k) is None]
    if missing:
        raise KeyError(f"missing required core columns: {missing}")
    return sel, norm

def _process_block(df: pd.DataFrame, sel: Dict[str, Optional[str]], norm: Dict[str, str]) -> pd.DataFrame:
    out = pd.DataFrame(index=df.index)

    # ---- IP/ports ----
    # Try explicit columns; else parse Flow ID; else sentinels.
    if sel.get("src_ip") and sel.get("dst_ip"):
        out["src_ip"] = df[sel["src_ip"]].astype(str)
        out["dst_ip"] = df[sel["dst_ip"]].astype(str)
    elif sel.get("flow_id"):
        s_ip, d_ip, s_po, d_po, _ = _parse_flow_id(df[sel["flow_id"]])
        out["src_ip"] = s_ip
        out["dst_ip"] = d_ip
        out["src_port"] = s_po
        out["dst_port"] = d_po
    else:
        out["src_ip"] = "0.0.0.0"
        out["dst_ip"] = "0.0.0.0"

    # Ports (prefer explicit columns when present)
    if "src_port" not in out:
        if sel.get("src_port"):
            out["src_port"] = pd.to_numeric(df[sel["src_port"]], errors="coerce").fillna(0).astype(int)
        else:
            out["src_port"] = 0
    if "dst_port" not in out:
        # parfois "Dst Port" existe alors que "src_port" non
        if sel.get("dst_port"):
            out["dst_port"] = pd.to_numeric(df[sel["dst_port"]], errors="coerce").fillna(0).astype(int)
        else:
            out["dst_port"] = 0

    # ---- Protocol ----
    proto_raw = df[sel["protocol"]]
    if np.issubdtype(proto_raw.dtype, np.number):
        out["protocol"] = proto_raw.map(PROTO_MAP).fillna("other")
    else:
        out["protocol"] = (
            proto_raw.astype(str).str.lower().str.strip()
            .replace({"6": "tcp", "17": "udp"})
        )
        out.loc[~out["protocol"].isin(["tcp", "udp"]), "protocol"] = "other"

    # ---- Durations / IAT ----
    eps = 1e-6
    flow_dur_us = pd.to_numeric(df[sel["flow_duration_us"]], errors="coerce")
    out["flow_duration"] = (flow_dur_us / 1e6).fillna(0.0).clip(lower=eps)

    if sel.get("flow_iat_mean_us"):
        out["iat_mean"] = (pd.to_numeric(df[sel["flow_iat_mean_us"]], errors="coerce") / 1e6).fillna(0.0)
    else:
        out["iat_mean"] = 0.0
    if sel.get("flow_iat_std_us"):
        out["iat_std"] = (pd.to_numeric(df[sel["flow_iat_std_us"]], errors="coerce") / 1e6).fillna(0.0)
    else:
        out["iat_std"] = 0.0

    # ---- pkts/bytes ----
    fwd_pkts = pd.to_numeric(df[sel["fwd_pkts"]], errors="coerce").fillna(0)
    bwd_pkts = pd.to_numeric(df[sel["bwd_pkts"]], errors="coerce").fillna(0)
    fwd_bytes = pd.to_numeric(df[sel["fwd_bytes"]], errors="coerce").fillna(0)
    bwd_bytes = pd.to_numeric(df[sel["bwd_bytes"]], errors="coerce").fillna(0)

    out["bidirectional_packets"] = (fwd_pkts + bwd_pkts).astype("int64").clip(lower=1)
    out["bidirectional_bytes"]   = (fwd_bytes + bwd_bytes).astype("int64").clip(lower=0)
    out["mean_packet_size"]      = out["bidirectional_bytes"] / out["bidirectional_packets"]

    # ---- std_packet_size from "Pkt Len Std" ----
    pkt_len_std_col = sel.get("pkt_len_std")
    if pkt_len_std_col:
        out["std_packet_size"] = pd.to_numeric(df[pkt_len_std_col], errors="coerce").fillna(0.0)
    else:
        out["std_packet_size"] = 0.0  # fallback (rarement nécessaire)

    # ---- derived features expected by trainer ----
    out["bytes_per_packet"]   = (out["bidirectional_bytes"] / out["bidirectional_packets"]).astype(float)
    out["packets_per_second"] = (out["bidirectional_packets"] / out["flow_duration"]).astype(float)

    # ---- Flags ----
    for src_key, out_key in [("syn","tcp_syn_count"), ("fin","tcp_fin_count"), ("rst","tcp_rst_count")]:
        col = sel.get(src_key)
        if col:
            out[out_key] = pd.to_numeric(df[col], errors="coerce").fillna(0).astype(int)
        else:
            out[out_key] = 0

    # ---- Label ----
    lbl = df[sel["label_raw"]].astype(str).str.strip().str.upper()
    out["label"] = (lbl != "BENIGN").astype(int)

    # Keep only tcp/udp
    out = out[out["protocol"].isin(["tcp", "udp"])]

    # Final column order (exactly what trainer expects + id fields)
    keep = [
        "src_ip","dst_ip","src_port","dst_port","protocol",
        "flow_duration",
        "bidirectional_packets","bidirectional_bytes","mean_packet_size","std_packet_size",
        "tcp_syn_count","tcp_fin_count","tcp_rst_count",
        "iat_mean","iat_std","bytes_per_packet","packets_per_second",
        "label",
    ]
    for k in keep:
        if k not in out:
            # ensure column exists
            if k.endswith("_ip"):
                out[k] = "0.0.0.0"
            elif k.endswith("_port"):
                out[k] = 0
            elif k == "protocol":
                out[k] = "other"
            elif k == "label":
                out[k] = 0
            else:
                out[k] = 0.0
    return out[keep]

def _usable_file_header(path: str) -> Optional[Tuple[Dict[str, Optional[str]], Dict[str, str]]]:
    # Read just header (nrows=1) to decide if file is usable and to build the selector
    try:
        df_head = pd.read_csv(path, nrows=1, low_memory=False)
        sel, norm = _select_columns(df_head)
        return sel, norm
    except Exception as e:
        print("SKIP (header)", path, repr(e))
        return None

def process_file(path: str, target_rows: int, seed: int = 42) -> pd.DataFrame:
    # Stream in chunks and sample up to target_rows rows
    head = _usable_file_header(path)
    if head is None:
        return pd.DataFrame()
    sel, norm = head

    chunksize = 200_000  # tune if needed
    rng = np.random.default_rng(seed)
    taken = 0
    parts = []
    try:
        for chunk in pd.read_csv(path, chunksize=chunksize, low_memory=False):
            df_proc = _process_block(chunk, sel, norm)
            if target_rows <= 0:
                parts.append(df_proc)
                continue
            if taken >= target_rows:
                break
            need = target_rows - taken
            if len(df_proc) <= need:
                parts.append(df_proc)
                taken += len(df_proc)
            else:
                frac = need / len(df_proc)
                sample = df_proc.sample(frac=frac, random_state=int(rng.integers(0, 2**31-1)))
                parts.append(sample)
                taken += len(sample)
                if taken >= target_rows:
                    break
    except Exception as e:
        print("SKIP (read)", path, repr(e))
        return pd.DataFrame()

    if not parts:
        return pd.DataFrame()
    return pd.concat(parts, ignore_index=True)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in_glob", required=True,
                    help='ex: "data/raw/csecic2018/*TrafficForML_CICFlowMeter*.csv"')
    ap.add_argument("--out_csv", required=True)
    ap.add_argument("--limit", type=int, default=0,
                    help="max total rows across all files (sampled per file). 0 = take all (can be huge).")
    args = ap.parse_args()

    files = sorted(glob.glob(args.in_glob))
    if not files:
        raise SystemExit(f"No files matched: {args.in_glob}")

    # Probe which files are usable
    usable = []
    for f in files:
        if _usable_file_header(f) is not None:
            usable.append(f)
        else:
            print("SKIP", f, "→ missing core columns")

    if not usable:
        raise SystemExit("No usable files found.")

    # Decide per-file sampling target if limit > 0
    per_file_target = 0
    remainder = 0
    if args.limit > 0:
        per_file_target = args.limit // len(usable)
        remainder = args.limit % len(usable)

    parts = []
    for i, f in enumerate(usable):
        tgt = 0
        if args.limit > 0:
            tgt = per_file_target + (1 if i < remainder else 0)
        print(f"Processing {f} target_rows={tgt if tgt>0 else 'ALL'}")
        df_part = process_file(f, tgt)
        if not df_part.empty:
            parts.append(df_part)
            print("OK", f, "rows:", len(df_part))
        else:
            print("SKIP", f, "→ no rows after processing")

    big = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()
    if big.empty:
        raise SystemExit("No data produced. Check inputs/columns.")

    big.to_csv(args.out_csv, index=False)
    print("Wrote", args.out_csv, "rows:", len(big))

if __name__ == "__main__":
    main()
