#!/usr/bin/env python3
"""Trace-derived calibration of the CAAC simulator against public IoT traffic.

The simulator is *not* a replay of these captures. This script fits the
traffic-intensity priors that the simulator uses for its network context feature
(``log1p(packets/s)``) and reports how far the simulated benign-to-attack contrast
is from the measured one.

Source: IoT-23 (Garcia, Parmisano & Erquiaga, 2020), individual-scenario Zeek
``conn.log.labeled`` files, downloaded from the public CTU mirror. Three captures
are used: one honeypot (benign) capture and two malware captures that contain both
benign and malicious flows. The exact URLs and SHA-256 digests are recorded in the
output JSON so the calibration is reproducible.

Everything here is deterministic except the bootstrap (seeded). The script caches
downloads in ``experiments/data`` and never writes outside the project.

Usage
-----
    python3 trace_calibration.py                 # download if needed, fit, write
    python3 trace_calibration.py --refresh       # re-download
    python3 trace_calibration.py --no-download   # fail if a capture is missing
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import sys
import urllib.request
from collections import Counter

import numpy as np

BASE_URL = ("https://mcfp.felk.cvut.cz/publicDatasets/IoT-23-Dataset/"
            "IndividualScenarios/")
CAPTURES = [
    ("CTU-Honeypot-Capture-5-1/bro/conn.log.labeled", "benign.log", "honeypot"),
    ("CTU-IoT-Malware-Capture-8-1/bro/conn.log.labeled", "malware8.log", "malware"),
    ("CTU-IoT-Malware-Capture-34-1/bro/conn.log.labeled", "malware34.log", "malware"),
]
HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(HERE, "data")
RESULTS_DIR = os.path.join(HERE, "results")
BIN_SECONDS = 60.0
BOOTSTRAP = 2000
RNG = np.random.default_rng(20261112)


# --------------------------------------------------------------------------------------
# Download and parse
# --------------------------------------------------------------------------------------

def ensure_capture(url_path, name, refresh, allow_download):
    dest = os.path.join(DATA_DIR, name)
    if os.path.exists(dest) and not refresh:
        return dest
    if not allow_download:
        raise FileNotFoundError("missing capture and --no-download given: " + dest)
    os.makedirs(DATA_DIR, exist_ok=True)
    url = BASE_URL + url_path
    print("downloading", url, "->", dest)
    tmp = dest + ".part"
    req = urllib.request.Request(url, headers={"User-Agent": "scholar-agent/1.0"})
    with urllib.request.urlopen(req, timeout=180) as r, open(tmp, "wb") as fh:
        while True:
            chunk = r.read(1 << 20)
            if not chunk:
                break
            fh.write(chunk)
    os.replace(tmp, dest)
    return dest


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_conn_log(path):
    """Return a list of (ts, duration, packets, label) from a Zeek conn.log."""
    rows = []
    fields = None
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                # Some mirrors pack the last three columns into one space-separated
                # field: "tunnel_parents label detailed-label".
                if len(fields[-1].split()) == 3:
                    fields = fields[:-1] + fields[-1].split()
                continue
            if line.startswith("#") or not line:
                continue
            parts = line.split("\t")
            if len(parts) == len(fields) - 2:
                parts = parts[:-1] + parts[-1].split(None, 2)
            if len(parts) != len(fields):
                continue
            d = dict(zip(fields, parts))
            try:
                ts = float(d["ts"])
            except (KeyError, ValueError):
                continue

            def num(key):
                try:
                    return float(d.get(key, "-"))
                except ValueError:
                    return 0.0

            label = d.get("label", "").strip().lower()
            if label not in ("benign", "malicious"):
                continue
            rows.append((ts, num("duration"), num("orig_pkts") + num("resp_pkts"), label))
    return rows


# --------------------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------------------

def binned_rate(rows, label, bin_seconds=BIN_SECONDS):
    """Packets/s in fixed bins, spreading each flow uniformly over its duration."""
    sel = [r for r in rows if r[3] == label and r[2] > 0]
    if not sel:
        return np.array([])
    t0 = min(r[0] for r in sel)
    span = max(r[0] for r in sel) - t0
    nb = int(math.ceil(span / bin_seconds)) + 2
    bins = np.zeros(nb)
    for ts, dur, pkts, _ in sel:
        dur = max(0.0, min(dur, 3600.0))
        a = (ts - t0) / bin_seconds
        if dur < 1e-6:
            i = min(max(int(a), 0), nb - 1)
            bins[i] += pkts
            continue
        b = a + dur / bin_seconds
        ia, ib = int(a), min(int(b), nb - 1)
        if ia == ib:
            bins[min(ia, nb - 1)] += pkts
            continue
        w = dur / bin_seconds
        for i in range(ia, ib + 1):
            lo, hi = max(a, i), min(b, i + 1)
            bins[i] += pkts * max(0.0, hi - lo) / w
    return bins[bins > 0] / bin_seconds


def describe(rows, label):
    sel = [r for r in rows if r[3] == label and r[2] > 0]
    if not sel:
        return None
    ts = np.array([r[0] for r in sel])
    pk = np.array([r[2] for r in sel])
    span = float(ts.max() - ts.min())
    rate = binned_rate(rows, label)
    log_rate = np.log(rate) if len(rate) else np.array([])
    inter = np.diff(np.sort(ts))
    inter = inter[inter > 0]
    return {
        "flows": int(len(sel)),
        "packets": float(pk.sum()),
        "span_s": round(span, 1),
        "aggregate_pkt_per_s": round(float(pk.sum() / max(span, 1.0)), 4),
        "flow_pkts_median": float(np.median(pk)),
        "flow_pkts_p95": float(np.percentile(pk, 95)),
        "flow_pkts_mean": float(pk.mean()),
        "bins_60s": int(len(rate)),
        "bin_rate_median": float(np.median(rate)) if len(rate) else None,
        "bin_rate_p95": float(np.percentile(rate, 95)) if len(rate) else None,
        "log_rate_mu": float(log_rate.mean()) if len(log_rate) else None,
        "log_rate_sigma": float(log_rate.std()) if len(log_rate) else None,
        "interarrival_median_s": float(np.median(inter)) if len(inter) else None,
    }


def mean_log_contrast(benign_rates, malicious_rates):
    """Contrast estimator used throughout: mean log-rate difference.

    This is the same quantity reported as ``mu_malicious - mu_benign`` in the
    per-capture descriptors and used to set the simulator prior, so the point
    estimate, the table and the calibration target cannot disagree.
    """
    return float(np.log(malicious_rates).mean() - np.log(benign_rates).mean())


def bootstrap_log_contrast(by_capture, n=BOOTSTRAP, rng=RNG):
    """Stratified bin bootstrap of the mean-log-rate contrast.

    Each capture is resampled bin-wise with replacement and the captures are then
    combined with their original weighting, so the per-capture composition is
    preserved. The interval does not account for autocorrelation between
    consecutive 60 s bins within a capture; the per-capture contrasts are reported
    alongside it so that between-capture heterogeneity is visible.
    """
    usable = [(b, m) for b, m in by_capture.values() if len(b) > 1 and len(m) > 1]
    if not usable:
        return None
    point = mean_log_contrast(np.concatenate([b for b, _ in usable]),
                              np.concatenate([m for _, m in usable]))
    est = []
    for _ in range(n):
        bs = [rng.choice(b, len(b), replace=True) for b, _ in usable]
        ms = [rng.choice(m, len(m), replace=True) for _, m in usable]
        est.append(mean_log_contrast(np.concatenate(bs), np.concatenate(ms)))
    est = np.array(est)
    return {
        "point": point,
        "ci95": [float(np.percentile(est, 2.5)), float(np.percentile(est, 97.5))],
        "n_bootstrap": int(n),
        "method": "stratified bin bootstrap (between-capture heterogeneity shown separately)",
    }


# --------------------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--refresh", action="store_true")
    ap.add_argument("--no-download", action="store_true")
    ap.add_argument("--out", default=os.path.join(RESULTS_DIR, "trace_priors.json"))
    ap.add_argument("--figure", default=os.path.join(RESULTS_DIR, "fig_trace_calibration.pdf"))
    args = ap.parse_args()

    captures = {}
    by_capture = {}
    for url_path, name, kind in CAPTURES:
        path = ensure_capture(url_path, name, args.refresh, not args.no_download)
        rows = parse_conn_log(path)
        labels = Counter(r[3] for r in rows)
        captures[name] = {
            "source": BASE_URL + url_path,
            "sha256": sha256(path),
            "kind": kind,
            "labels": dict(labels),
            "benign": describe(rows, "benign"),
            "malicious": describe(rows, "malicious"),
        }
        by_capture[name] = (binned_rate(rows, "benign"),
                            binned_rate(rows, "malicious"))
        print("{:14s} {:6d} flows  benign={:6d} malicious={:6d}".format(
            name, len(rows), labels.get("benign", 0), labels.get("malicious", 0)))

    # The contrast is estimated only within captures that contain both labels, so
    # that a device/context difference between captures cannot masquerade as an
    # attack effect. The benign-only honeypot capture is reported descriptively.
    usable = {n: (b, m) for n, (b, m) in by_capture.items()
              if len(b) > 1 and len(m) > 1}
    all_benign = np.concatenate([b for b, _ in usable.values()])
    all_malicious = np.concatenate([m for _, m in usable.values()])
    ratio = bootstrap_log_contrast(by_capture)
    per_capture = {
        name: mean_log_contrast(b, m)
        for name, (b, m) in by_capture.items()
        if len(b) > 1 and len(m) > 1
    }

    # The simulator's network feature is log1p(packets/s) per node. Its benign mean is a
    # design baseline (absolute rates are not comparable to a sparse honeypot capture);
    # its DoS mean is *calibrated* to the measured benign->malicious log-rate contrast.
    sim_benign = 4.20
    sim_dos = sim_benign + (ratio["point"] if ratio else 2.0)
    sim_contrast = sim_dos - sim_benign
    if ratio:
        inside = ratio["ci95"][0] <= sim_contrast <= ratio["ci95"][1]
    else:
        inside = None

    out = {
        "dataset": "IoT-23 individual scenarios (Zeek conn.log.labeled)",
        "dataset_doi": "10.5281/zenodo.4743746",
        "bin_seconds": BIN_SECONDS,
        "captures": captures,
        "pooled": {
            "benign_bins": int(len(all_benign)),
            "malicious_bins": int(len(all_malicious)),
            "contrast_captures": sorted(usable),
            "benign_log_rate_mu": float(np.log(all_benign).mean()),
            "benign_log_rate_sigma": float(np.log(all_benign).std()),
            "malicious_log_rate_mu": float(np.log(all_malicious).mean()),
            "malicious_log_rate_sigma": float(np.log(all_malicious).std()),
            "log_rate_contrast": ratio,
            "per_capture_contrast": per_capture,
            "per_capture_contrast_range": ([min(per_capture.values()),
                                            max(per_capture.values())]
                                           if per_capture else None),
            "excluded_from_contrast": sorted(set(by_capture) - set(usable)),
        },
        "simulator": {
            "benign_log_pkt_mean": sim_benign,
            "dos_log_pkt_mean": sim_dos,
            "log_contrast": sim_contrast,
            "contrast_inside_trace_ci": inside,
        },
        "interpretation": (
            "Absolute rates are not directly comparable: the captures are sparse "
            "honeypot/C2 traces while the simulator models per-node application "
            "telemetry. Only the benign-to-attack mean-log-rate *contrast* is "
            "calibrated; the simulator's dispersion is narrower than the trace and "
            "is not claimed to match it."
        ),
    }
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print("\nwrote", args.out)
    if ratio:
        print("log-rate contrast (malicious/benign): {:.3f}  CI95 [{:.3f}, {:.3f}]".format(
            ratio["point"], *ratio["ci95"]))
    print("simulator contrast {:.2f} inside CI: {}".format(sim_contrast, inside))

    make_figure(all_benign, all_malicious, ratio, args.figure, sim_contrast)
    print("wrote", args.figure)


def make_figure(benign, malicious, ratio, path, sim_contrast=2.0):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    plt.rcParams.update({
        "font.size": 8, "axes.labelsize": 8, "axes.titlesize": 8,
        "legend.fontsize": 7, "xtick.labelsize": 7, "ytick.labelsize": 7,
        "figure.dpi": 300, "savefig.bbox": "tight", "pdf.fonttype": 42,
    })
    fig, ax = plt.subplots(1, 3, figsize=(7.2, 2.3))

    # (a) CCDF of packet rate per 60 s bin.
    for data, label, color in [(benign, "benign", "#1f77b4"),
                               (malicious, "malicious", "#d62728")]:
        x = np.sort(data)
        y = 1.0 - np.arange(1, len(x) + 1) / len(x)
        ax[0].loglog(x, np.maximum(y, 1e-4), color=color, lw=1.2,
                     label="{} (n={})".format(label, len(x)))
    ax[0].set_xlabel("packets/s per 60 s bin")
    ax[0].set_ylabel("CCDF")
    ax[0].set_title("(a) rate tail")
    ax[0].legend(frameon=False)

    # (b) log-rate histogram with a fitted normal.
    bins = np.linspace(min(np.log(benign).min(), np.log(malicious).min()),
                       max(np.log(benign).max(), np.log(malicious).max()), 40)
    ax[1].hist(np.log(benign), bins=bins, density=True, alpha=0.55,
               color="#1f77b4", label="benign")
    ax[1].hist(np.log(malicious), bins=bins, density=True, alpha=0.55,
               color="#d62728", label="malicious")
    for data, color in [(benign, "#1f77b4"), (malicious, "#d62728")]:
        mu, sd = np.log(data).mean(), np.log(data).std()
        xs = np.linspace(bins[0], bins[-1], 200)
        ax[1].plot(xs, np.exp(-0.5 * ((xs - mu) / sd) ** 2) / (sd * math.sqrt(2 * math.pi)),
                   color=color, lw=1.0)
    ax[1].set_xlabel(r"$\log$ packets/s")
    ax[1].set_ylabel("density")
    ax[1].set_title("(b) log-normal fit")
    ax[1].legend(frameon=False)

    # (c) contrast with bootstrap CI and the simulator's setting.
    if ratio:
        ax[2].bar([0], [ratio["point"]], color="#555555", width=0.5)
        ax[2].errorbar([0], [ratio["point"]],
                       yerr=[[ratio["point"] - ratio["ci95"][0]],
                             [ratio["ci95"][1] - ratio["point"]]],
                       fmt="none", ecolor="black", capsize=4)
        ax[2].axhline(sim_contrast, color="#2ca02c", ls="--", lw=1.2,
                      label="simulator ({:.2f})".format(sim_contrast))
        ax[2].set_xticks([0])
        ax[2].set_xticklabels(["trace"])
        ax[2].set_ylabel(r"$\log$ malicious/benign rate")
        ax[2].set_title("(c) contrast")
        ax[2].legend(frameon=False)
    fig.tight_layout()
    for ext in (".pdf", ".png"):
        fig.savefig(path.replace(".pdf", ext), dpi=300)
    plt.close(fig)


if __name__ == "__main__":
    main()
